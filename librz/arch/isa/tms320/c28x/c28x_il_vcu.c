// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * RzIL for the C28x VCU and VCU-II (SPRUHS1C chapters 3 to 5). VSTATUS is one
 * register whose fields the instructions set, laid out as on VCU-II, whose
 * bits 13-0 are VCU-I's.
 */

#include "c28x_il.h"

#include <rz_il/rz_il_opbuilder_begin.h>

typedef RzILOpEffect *(*C28xVcuLifter)(const C28xInsn *insn);

typedef enum {
	C28X_VS_SHIFTR,
	C28X_VS_SHIFTL,
	C28X_VS_SAT,
	C28X_VS_RND,
	C28X_VS_OVFR,
	C28X_VS_OVFI,
	C28X_VS_CPACK,
	C28X_VS_OPACK,
	C28X_VS_GFPOLY,
	C28X_VS_GFORDER,
	C28X_VS_K,
	C28X_VS_DIVE,
	C28X_VS_CRCMSGFLIP,
} C28xVstatusField;

/** \brief Each VSTATUS field's lowest bit and width (SPRUHS1C figure 5-3). */
static const struct {
	ut8 lo;
	ut8 width;
} c28x_vstatus[] = {
	[C28X_VS_SHIFTR] = { 0, 5 },
	[C28X_VS_SHIFTL] = { 5, 5 },
	[C28X_VS_SAT] = { 10, 1 },
	[C28X_VS_RND] = { 11, 1 },
	[C28X_VS_OVFR] = { 12, 1 },
	[C28X_VS_OVFI] = { 13, 1 },
	[C28X_VS_CPACK] = { 14, 1 },
	[C28X_VS_OPACK] = { 15, 1 },
	[C28X_VS_GFPOLY] = { 16, 8 },
	[C28X_VS_GFORDER] = { 24, 3 },
	[C28X_VS_K] = { 27, 3 },
	[C28X_VS_DIVE] = { 30, 1 },
	[C28X_VS_CRCMSGFLIP] = { 31, 1 },
};

/**
 * \brief Set VSTATUS field \p f to \p v, keeping the others.
 */
static RzILOpEffect *c28x_vs_set(C28xVstatusField f, RzILOpPure *v) {
	const ut32 mask = ((1U << c28x_vstatus[f].width) - 1) << c28x_vstatus[f].lo;
	RzILOpPure *keep = LOGAND(VARG("vstatus"), UN(32, ~mask));
	RzILOpPure *field = SHIFTL0(UNSIGNED(32, v), UN(8, c28x_vstatus[f].lo));
	return SETG("vstatus", LOGOR(keep, LOGAND(field, UN(32, mask))));
}

/**
 * \brief The instructions that set one VSTATUS field: to their immediate, or
 * to a constant.
 *
 * A_VCLROVFI clears OVFI: SPRUHS1C's VCU-II page says "real", but its VCU-I
 * page and the VSTATUS description name the imaginary flag.
 */
static const struct {
	bool set;
	bool imm;
	ut8 value;
	C28xVstatusField field;
} c28x_vcu_sets[] = {
	[C28X_INS_VSETSHL] = { true, true, 0, C28X_VS_SHIFTL },
	[C28X_INS_VSETSHR] = { true, true, 0, C28X_VS_SHIFTR },
	[C28X_INS_VSETK] = { true, true, 0, C28X_VS_K },
	[C28X_INS_VSATON] = { true, false, 1, C28X_VS_SAT },
	[C28X_INS_VSATOFF] = { true, false, 0, C28X_VS_SAT },
	[C28X_INS_VRNDON] = { true, false, 1, C28X_VS_RND },
	[C28X_INS_VRNDOFF] = { true, false, 0, C28X_VS_RND },
	[C28X_INS_A_VCLROVFI] = { true, false, 0, C28X_VS_OVFI },
	[C28X_INS_A_VCLROVFR] = { true, false, 0, C28X_VS_OVFR },
	[C28X_INS_VSETCPACK] = { true, false, 1, C28X_VS_CPACK },
	[C28X_INS_VCLRCPACK] = { true, false, 0, C28X_VS_CPACK },
	[C28X_INS_VSETOPACK] = { true, false, 1, C28X_VS_OPACK },
	[C28X_INS_VCLROPACK] = { true, false, 0, C28X_VS_OPACK },
	[C28X_INS_VSETCRCMSGFLIP] = { true, false, 1, C28X_VS_CRCMSGFLIP },
	[C28X_INS_VCLRCRCMSGFLIP] = { true, false, 0, C28X_VS_CRCMSGFLIP },
	[C28X_INS_VCLRDIVE] = { true, false, 0, C28X_VS_DIVE },
};

static RzILOpEffect *c28x_vcu_set(const C28xInsn *insn) {
	if ((size_t)insn->id >= RZ_ARRAY_SIZE(c28x_vcu_sets) || !c28x_vcu_sets[insn->id].set) {
		return NULL;
	}
	const C28xVstatusField field = c28x_vcu_sets[insn->id].field;
	if (!c28x_vcu_sets[insn->id].imm) {
		return c28x_vs_set(field, UN(8, c28x_vcu_sets[insn->id].value));
	}
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_IMM) {
		return NULL;
	}
	return c28x_vs_set(field, UN(8, insn->ops[0].imm & 0xff));
}

static const char *c28x_vr_names[] = {
	"vr0",
	"vr1",
	"vr2",
	"vr3",
	"vr4",
	"vr5",
	"vr6",
	"vr7",
	"vr8",
};

/**
 * \brief The IL global of VRa operand \p o.
 */
static const char *c28x_vr_name(const C28xOperand *o) {
	if (o->kind != C28X_OP_REG || o->reg < C28X_REG_VR0 || o->reg > C28X_REG_VR0 + 8) {
		return NULL;
	}
	return c28x_vr_names[o->reg - C28X_REG_VR0];
}

/**
 * \brief VCLEAR VRa, VCLEARALL, VTCLEAR and VCRCCLR.
 *
 * VCLEARALL clears VR0-VR8, VT0 and VT1 as its description says; a VCU-II
 * example's comment also names VSM0-VSM63, which the description doesn't.
 */
static RzILOpEffect *c28x_vcu_clear(const C28xInsn *insn) {
	if (insn->id == C28X_INS_VCLEAR) {
		const char *n = insn->nops == 1 ? c28x_vr_name(&insn->ops[0]) : NULL;
		return n ? SETG(n, UN(32, 0)) : NULL;
	}
	if (insn->id == C28X_INS_VCRCCLR) {
		return SETG("vcrc", UN(32, 0));
	}
	RzILOpEffect *eff = SEQ2(SETG("vt0", UN(32, 0)), SETG("vt1", UN(32, 0)));
	if (insn->id == C28X_INS_VCLEARALL) {
		for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_vr_names); i++) {
			eff = SEQ2(eff, SETG(c28x_vr_names[i], UN(32, 0)));
		}
	}
	return eff;
}

static const char *c28x_vsm_names[] = {
	"vsm0",
	"vsm1",
	"vsm2",
	"vsm3",
	"vsm4",
	"vsm5",
	"vsm6",
	"vsm7",
	"vsm8",
	"vsm9",
	"vsm10",
	"vsm11",
	"vsm12",
	"vsm13",
	"vsm14",
	"vsm15",
	"vsm16",
	"vsm17",
	"vsm18",
	"vsm19",
	"vsm20",
	"vsm21",
	"vsm22",
	"vsm23",
	"vsm24",
	"vsm25",
	"vsm26",
	"vsm27",
	"vsm28",
	"vsm29",
	"vsm30",
	"vsm31",
	"vsm32",
	"vsm33",
	"vsm34",
	"vsm35",
	"vsm36",
	"vsm37",
	"vsm38",
	"vsm39",
	"vsm40",
	"vsm41",
	"vsm42",
	"vsm43",
	"vsm44",
	"vsm45",
	"vsm46",
	"vsm47",
	"vsm48",
	"vsm49",
	"vsm50",
	"vsm51",
	"vsm52",
	"vsm53",
	"vsm54",
	"vsm55",
	"vsm56",
	"vsm57",
	"vsm58",
	"vsm59",
	"vsm60",
	"vsm61",
	"vsm62",
	"vsm63",
};

/**
 * \brief The IL global of a whole 32-bit VCU register operand.
 */
static const char *c28x_vcu_reg32(const C28xOperand *o) {
	if (o->kind != C28X_OP_REG) {
		return NULL;
	}
	switch (o->reg) {
	case C28X_REG_VT0: return "vt0";
	case C28X_REG_VT0 + 1: return "vt1";
	case C28X_REG_VSTATUS: return "vstatus";
	case C28X_REG_VCRC: return "vcrc";
	case C28X_REG_VCRCPOLY: return "vcrcpoly";
	case C28X_REG_VCRCSIZE: return "vcrcsize";
	default: return c28x_vr_name(o);
	}
}

/**
 * \brief Read VCU register operand \p o: a whole register, VRaL or VRaH, or the
 * state-metric pair VSM(2n+1):VSM(2n), VSM(2n+1) in the high half.
 */
static RzILOpPure *c28x_vcu_read(const C28xOperand *o) {
	if (o->kind == C28X_OP_VSMPAIR) {
		const ut32 n = (ut32)o->imm & 31;
		return APPEND(VARG(c28x_vsm_names[2 * n + 1]), VARG(c28x_vsm_names[2 * n]));
	}
	if (o->kind == C28X_OP_REG_LOW || o->kind == C28X_OP_REG_HIGH) {
		const C28xOperand whole = { .kind = C28X_OP_REG, .reg = o->reg };
		const char *n = c28x_vr_name(&whole);
		if (!n) {
			return NULL;
		}
		RzILOpPure *v = VARG(n);
		return UNSIGNED(16, o->kind == C28X_OP_REG_HIGH ? SHIFTR0(v, UN(8, 16)) : v);
	}
	const char *n = c28x_vcu_reg32(o);
	return n ? VARG(n) : NULL;
}

/**
 * \brief Write \p v to VCU register operand \p o, keeping the other half of
 * VRa.
 */
static RzILOpEffect *c28x_vcu_write(const C28xOperand *o, RzILOpPure *v) {
	if (o->kind == C28X_OP_VSMPAIR) {
		const ut32 n = (ut32)o->imm & 31;
		RzILOpPure *high = UNSIGNED(16, SHIFTR0(v, UN(8, 16)));
		RzILOpEffect *hi = SETG(c28x_vsm_names[2 * n + 1], high);
		return SEQ2(hi, SETG(c28x_vsm_names[2 * n], UNSIGNED(16, DUP(v))));
	}
	if (o->kind == C28X_OP_REG_LOW || o->kind == C28X_OP_REG_HIGH) {
		const C28xOperand whole = { .kind = C28X_OP_REG, .reg = o->reg };
		const char *n = c28x_vr_name(&whole);
		if (!n) {
			rz_il_op_pure_free(v);
			return NULL;
		}
		RzILOpPure *w = UNSIGNED(32, v);
		if (o->kind == C28X_OP_REG_HIGH) {
			RzILOpPure *low = LOGAND(VARG(n), UN(32, 0xffff));
			return SETG(n, LOGOR(low, SHIFTL0(w, UN(8, 16))));
		}
		return SETG(n, LOGOR(LOGAND(VARG(n), UN(32, 0xffff0000)), w));
	}
	const char *n = c28x_vcu_reg32(o);
	if (!n) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	return SETG(n, v);
}

/**
 * \brief Set a VCRCSIZE field: DSIZE is bits 2:0, PSIZE bits 20:16 (SPRUHS1C
 * table 5-8).
 */
static RzILOpEffect *c28x_vcrcsize_set(bool psize, RzILOpPure *v) {
	const ut32 lo = psize ? 16 : 0;
	const ut32 mask = (psize ? 0x1fU : 0x7U) << lo;
	RzILOpPure *field = LOGAND(SHIFTL0(UNSIGNED(32, v), UN(8, lo)), UN(32, mask));
	return SETG("vcrcsize", LOGOR(LOGAND(VARG("vcrcsize"), UN(32, ~mask)), field));
}

/**
 * \brief A move's source other than memory: a VCU register, a 16-bit data
 * address or a CPU register.
 */
static RzILOpPure *c28x_vcu_src(const C28xOperand *o, bool wide) {
	if (o->kind == C28X_OP_DMA) {
		return LOADW(wide ? 32 : 16, c28x_byte(UN(32, (ut64)o->imm / C28X_WORD_BYTES)));
	}
	if (o->kind == C28X_OP_MEM) {
		const char *cpu = c28x_reg32(o);
		return cpu ? VARG(cpu) : NULL;
	}
	return c28x_vcu_read(o);
}

/**
 * \brief A move's destination other than memory.
 *
 * VMOV16 VCRCDSIZE/VCRCPSIZE,mem16 set their VCRCSIZE fields, as their
 * pseudocode says, rather than the whole halves their titles mention.
 */
static RzILOpEffect *c28x_vcu_dst(const C28xOperand *o, RzILOpPure *v) {
	const bool psize = o->kind == C28X_OP_REG && o->reg == C28X_REG_VCRCPSIZE;
	if (psize || (o->kind == C28X_OP_REG && o->reg == C28X_REG_VCRCDSIZE)) {
		return c28x_vcrcsize_set(psize, v);
	}
	if (o->kind == C28X_OP_DMA) {
		return STOREW(c28x_byte(UN(32, (ut64)o->imm / C28X_WORD_BYTES)), v);
	}
	if (o->kind == C28X_OP_MEM) {
		const char *cpu = c28x_reg32(o);
		if (!cpu) {
			rz_il_op_pure_free(v);
			return NULL;
		}
		return SETG(cpu, v);
	}
	return c28x_vcu_write(o, v);
}

/**
 * \brief VMOV32 and VMOV16 between VCU registers, their halves, VSM pairs and
 * memory, and VMOV32 between a loc32 and a 16-bit data address. The access
 * width is the mnemonic's, whatever width the row renders mem32 with.
 */
static RzILOpEffect *c28x_vcu_mov(const C28xInsn *insn) {
	if (insn->nops != 2) {
		return NULL;
	}
	const bool wide = insn->id == C28X_INS_VMOV32;
	const C28xOperand *dst = &insn->ops[0];
	const C28xOperand *src = &insn->ops[1];
	if (c28x_is_mem(dst)) {
		RzILOpPure *v = c28x_vcu_src(src, wide);
		return v ? c28x_with_mem(dst, wide, c28x_ea_store(v)) : NULL;
	}
	if (c28x_is_mem(src)) {
		RzILOpEffect *wr = c28x_vcu_dst(dst, VARL("mv"));
		RzILOpEffect *load = wr ? SETL("mv", c28x_ea_load(wide ? 32 : 16)) : NULL;
		return load ? c28x_with_mem(src, wide, SEQ2(load, wr)) : NULL;
	}
	RzILOpPure *v = c28x_vcu_src(src, wide);
	return v ? c28x_vcu_dst(dst, v) : NULL;
}

/**
 * \brief VMOVZI, VMOVXI and VMOVIX: VRa or VCRCPOLY takes a 16-bit immediate in
 * its low half (VMOVZI clearing the high one) or its high half.
 */
static RzILOpEffect *c28x_vcu_movi(const C28xInsn *insn) {
	if (insn->nops != 2 || insn->ops[1].kind != C28X_OP_IMM) {
		return NULL;
	}
	RzILOpPure *cur = c28x_vcu_read(&insn->ops[0]);
	if (!cur) {
		return NULL;
	}
	const ut32 imm = (ut32)insn->ops[1].imm & 0xffff;
	RzILOpPure *v;
	if (insn->id == C28X_INS_VMOVZI) {
		rz_il_op_pure_free(cur);
		v = UN(32, imm);
	} else if (insn->id == C28X_INS_VMOVXI) {
		v = LOGOR(LOGAND(cur, UN(32, 0xffff0000)), UN(32, imm));
	} else {
		v = LOGOR(LOGAND(cur, UN(32, 0xffff)), UN(32, imm << 16));
	}
	return c28x_vcu_write(&insn->ops[0], v);
}

/**
 * \brief VMOVD32 VRa,mem32 loads VRa and, as its pseudocode says, copies
 * [mem32] two words up; its prose says the copy goes the other way.
 */
static RzILOpEffect *c28x_vcu_movd32(const C28xInsn *insn) {
	if (insn->nops != 2 || !c28x_is_mem(&insn->ops[1])) {
		return NULL;
	}
	RzILOpEffect *wr = c28x_vcu_write(&insn->ops[0], VARL("mv"));
	if (!wr) {
		return NULL;
	}
	RzILOpPure *above = c28x_byte(ADD(VARL(C28X_EA_LOCAL), UN(32, 2)));
	RzILOpEffect *body = SEQ3(SETL("mv", c28x_ea_load(32)), wr, STOREW(above, VARL("mv")));
	return c28x_with_mem(&insn->ops[1], true, body);
}

/**
 * \brief VSWAP32 VRb,VRa.
 */
static RzILOpEffect *c28x_vcu_swap(const C28xInsn *insn) {
	const char *a = insn->nops == 2 ? c28x_vr_name(&insn->ops[0]) : NULL;
	const char *b = a ? c28x_vr_name(&insn->ops[1]) : NULL;
	if (!b) {
		return NULL;
	}
	return SEQ3(SETL("sa", VARG(a)), SETG(a, VARG(b)), SETG(b, VARL("sa")));
}

/**
 * \brief VXORMOV32 VRa,mem32: a 32-bit access, though the row renders mem32 as
 * loc16.
 */
static RzILOpEffect *c28x_vcu_xormov(const C28xInsn *insn) {
	const char *a = insn->nops == 2 ? c28x_vr_name(&insn->ops[0]) : NULL;
	if (!a || !c28x_is_mem(&insn->ops[1])) {
		return NULL;
	}
	return c28x_with_mem(&insn->ops[1], true, SETG(a, LOGXOR(VARG(a), c28x_ea_load(32))));
}

/**
 * \brief VSETCRCSIZE #5I:#3i sets PSIZE and DSIZE.
 */
static RzILOpEffect *c28x_vcu_setcrcsize(const C28xInsn *insn) {
	const C28xOperand *op = insn->ops;
	if (insn->nops != 2 || op[0].kind != C28X_OP_IMMDEC || op[1].kind != C28X_OP_IMMCOLON) {
		return NULL;
	}
	RzILOpEffect *p = c28x_vcrcsize_set(true, UN(8, insn->ops[0].imm & 0x1f));
	return SEQ2(p, c28x_vcrcsize_set(false, UN(8, insn->ops[1].imm & 0x7)));
}

/*
 * CRC: MSB-first CRCs over bytes, or over bit strings VCRCSIZE configures,
 * accumulated in VCRC from bit 0 up. TI's linker's CRC tables (CRC8_PRIME,
 * CRC16_ALT, CRC16_802_15_4, CRC24_FLEXRAY, CRC32_PRIME and CRC32_C) are these
 * CRCs from zero over each word's low byte, then its high one.
 */

/**
 * \brief The fixed-polynomial CRC instructions: CRC width and polynomial, and
 * whether they take mem16's high byte.
 *
 * SPRUHS1C's VCRC32P2 pages repeat polynomial 1; TI's CRC application note
 * SPRACR3 gives 0x1EDC6F41, as TI's linker's CRC32_C tables confirm.
 */
static const struct {
	ut8 width;
	bool high;
	ut32 poly;
} c28x_vcrcs[] = {
	[C28X_INS_VCRC8L_1] = { 8, false, 0x07 },
	[C28X_INS_VCRC8H_1] = { 8, true, 0x07 },
	[C28X_INS_VCRC16P1L_1] = { 16, false, 0x8005 },
	[C28X_INS_VCRC16P1H_1] = { 16, true, 0x8005 },
	[C28X_INS_VCRC16P2L_1] = { 16, false, 0x1021 },
	[C28X_INS_VCRC16P2H_1] = { 16, true, 0x1021 },
	[C28X_INS_VCRC24L_1] = { 24, false, 0x5d6dcb },
	[C28X_INS_VCRC24H_1] = { 24, true, 0x5d6dcb },
	[C28X_INS_VCRC32L_1] = { 32, false, 0x04c11db7 },
	[C28X_INS_VCRC32H_1] = { 32, true, 0x04c11db7 },
	[C28X_INS_VCRC32P2L_1] = { 32, false, 0x1edc6f41 },
	[C28X_INS_VCRC32P2H_1] = { 32, true, 0x1edc6f41 },
};

static RzILOpBool *c28x_vs_bit(C28xVstatusField f) {
	return NON_ZERO(LOGAND(VARG("vstatus"), UN(32, 1U << c28x_vstatus[f].lo)));
}

/**
 * \brief The low eight bits of the value in \p local in reverse order.
 */
static RzILOpPure *c28x_rev8(const char *local) {
	RzILOpPure *r = UN(32, 0);
	for (ut32 i = 0; i < 8; i++) {
		RzILOpPure *bit = LOGAND(SHIFTR0(VARL(local), UN(8, i)), UN(32, 1));
		r = LOGOR(r, SHIFTL0(bit, UN(8, 7 - i)));
	}
	return r;
}

/**
 * \brief Latch mem16's low or high byte in "cd", reversed when \p flip and
 * CRCMSGFLIP is set; mem16 is read in "cb".
 */
static RzILOpEffect *c28x_crc_byte(bool high, bool flip) {
	RzILOpPure *lane = high ? SHIFTR0(VARL("cb"), UN(8, 8)) : VARL("cb");
	RzILOpEffect *load = SETL("cb", UNSIGNED(32, c28x_ea_load(16)));
	RzILOpEffect *byte = SETL("cd", LOGAND(lane, UN(32, 0xff)));
	if (!flip) {
		return SEQ2(load, byte);
	}
	RzILOpPure *flipped = ITE(c28x_vs_bit(C28X_VS_CRCMSGFLIP), c28x_rev8("cd"), VARL("cd"));
	return SEQ3(load, byte, SETL("cd", flipped));
}

/**
 * \brief The VCRC8/16/24/32 instructions, each feeding one byte, MSB first.
 */
static RzILOpEffect *c28x_vcu_crc(const C28xInsn *insn) {
	if ((size_t)insn->id >= RZ_ARRAY_SIZE(c28x_vcrcs) || !c28x_vcrcs[insn->id].width) {
		return NULL;
	}
	if (insn->nops != 1 || !c28x_is_mem(&insn->ops[0])) {
		return NULL;
	}
	const ut32 w = c28x_vcrcs[insn->id].width;
	const ut32 mask = (ut32)((1ULL << w) - 1);
	RzILOpPure *seed = LOGAND(VARG("vcrc"), UN(32, mask));
	RzILOpEffect *body = SEQ2(c28x_crc_byte(c28x_vcrcs[insn->id].high, true),
		SETL("cr", LOGXOR(seed, SHIFTL0(VARL("cd"), UN(8, w - 8)))));
	for (ut32 i = 0; i < 8; i++) {
		RzILOpPure *shifted = LOGAND(SHIFTL0(VARL("cr"), UN(8, 1)), UN(32, mask));
		RzILOpBool *top = NON_ZERO(LOGAND(VARL("cr"), UN(32, 1U << (w - 1))));
		RzILOpPure *poly = UN(32, c28x_vcrcs[insn->id].poly);
		RzILOpPure *next = ITE(top, LOGXOR(shifted, poly), DUP(shifted));
		body = SEQ2(body, SETL("cr", next));
	}
	RzILOpPure *keep = LOGAND(VARG("vcrc"), UN(32, ~mask));
	body = SEQ2(body, SETG("vcrc", LOGOR(keep, VARL("cr"))));
	return c28x_with_mem(&insn->ops[0], false, body);
}

/**
 * \brief VCRCL and VCRCH: the CRC of DSIZE + 1 bits from mem16's low or high
 * byte, right justified, with the PSIZE + 1 bit polynomial in VCRCPOLY
 * (SPRUHS1C tables 4-3 and 4-4), fed MSB first.
 */
static RzILOpEffect *c28x_vcu_crcgen(const C28xInsn *insn) {
	if (insn->nops != 1 || !c28x_is_mem(&insn->ops[0])) {
		return NULL;
	}
	// gd: data bits, gw: CRC bits, gm: the CRC's mask, gp: the polynomial
	RzILOpPure *d = ADD(LOGAND(VARG("vcrcsize"), UN(32, 7)), UN(32, 1));
	RzILOpPure *w = ADD(LOGAND(SHIFTR0(VARG("vcrcsize"), UN(8, 16)), UN(32, 0x1f)), UN(32, 1));
	RzILOpPure *m = UNSIGNED(32, SUB(SHIFTL0(UN(64, 1), VARL("gw")), UN(64, 1)));
	RzILOpEffect *sizes = SEQ4(SETL("gd", d), SETL("gw", w), SETL("gm", m),
		SETL("gp", LOGAND(VARG("vcrcpoly"), VARL("gm"))));
	// CRCMSGFLIP reverses the data bits alone: reversing the byte leaves them on top
	RzILOpPure *flipped = SHIFTR0(c28x_rev8("cd"), SUB(UN(32, 8), VARL("gd")));
	RzILOpPure *dmask = SUB(SHIFTL0(UN(32, 1), VARL("gd")), UN(32, 1));
	RzILOpBool *flip = c28x_vs_bit(C28X_VS_CRCMSGFLIP);
	RzILOpEffect *data = SETL("cd", LOGAND(ITE(flip, flipped, VARL("cd")), dmask));
	RzILOpEffect *body = SEQ4(sizes, c28x_crc_byte(insn->id == C28X_INS_VCRCH, false), data,
		SETL("cr", LOGAND(VARG("vcrc"), VARL("gm"))));
	for (ut32 j = 0; j < 8; j++) {
		RzILOpPure *at = SUB(SUB(VARL("gd"), UN(32, 1)), UN(32, j));
		RzILOpPure *bit = LOGAND(SHIFTR0(VARL("cd"), at), UN(32, 1));
		RzILOpPure *msb = SUB(VARL("gw"), UN(32, 1));
		RzILOpPure *top = LOGAND(SHIFTR0(VARL("cr"), msb), UN(32, 1));
		RzILOpPure *shifted = LOGAND(SHIFTL0(VARL("cr"), UN(8, 1)), VARL("gm"));
		RzILOpBool *fb = NON_ZERO(LOGXOR(bit, top));
		RzILOpPure *next = ITE(fb, LOGXOR(shifted, VARL("gp")), DUP(shifted));
		RzILOpBool *active = ULT(UN(32, j), VARL("gd"));
		body = SEQ2(body, SETL("cr", ITE(active, next, VARL("cr"))));
	}
	RzILOpPure *keep = LOGAND(VARG("vcrc"), LOGNOT(VARL("gm")));
	body = SEQ2(body, SETG("vcrc", LOGOR(keep, VARL("cr"))));
	return c28x_with_mem(&insn->ops[0], false, body);
}

/**
 * \brief VSWAPCRC swaps VCRC's low two bytes.
 */
static RzILOpEffect *c28x_vcu_swapcrc(RZ_UNUSED const C28xInsn *insn) {
	RzILOpPure *low = SHIFTL0(LOGAND(VARG("vcrc"), UN(32, 0xff)), UN(8, 8));
	RzILOpPure *high = LOGAND(SHIFTR0(VARG("vcrc"), UN(8, 8)), UN(32, 0xff));
	return SETG("vcrc", LOGOR(LOGAND(VARG("vcrc"), UN(32, 0xffff0000)), LOGOR(low, high)));
}

/**
 * \brief VLSHL32, VLSHR32, VASHL32 and VASHR32 VRa by a 5-bit immediate.
 *
 * VASHL32 latches OVFR when the signed result overflows, whatever SAT says,
 * and saturates it when SAT is set; VASHR32 adds half of the last place
 * shifted out before truncating when RND is set (SPRUHS1C section 5.6).
 */
static RzILOpEffect *c28x_vcu_shift(const C28xInsn *insn) {
	const char *a = insn->nops == 2 ? c28x_vr_name(&insn->ops[0]) : NULL;
	const C28xOpKind k = insn->ops[1].kind;
	if (!a || (k != C28X_OP_VSHL && k != C28X_OP_VSHR)) {
		return NULL;
	}
	const ut32 n = (ut32)insn->ops[1].imm & 31;
	if (insn->id == C28X_INS_VLSHL32) {
		return SETG(a, SHIFTL0(VARG(a), UN(8, n)));
	}
	if (insn->id == C28X_INS_VLSHR32) {
		return SETG(a, SHIFTR0(VARG(a), UN(8, n)));
	}
	if (insn->id == C28X_INS_VASHR32) {
		RzILOpPure *half = UN(64, n ? 1ULL << (n - 1) : 0);
		RzILOpPure *rnd = UNSIGNED(32, SHIFTRA(ADD(SIGNED(64, VARG(a)), half), UN(8, n)));
		RzILOpPure *trunc = UNSIGNED(32, SHIFTRA(SIGNED(64, VARG(a)), UN(8, n)));
		return SETG(a, ITE(c28x_vs_bit(C28X_VS_RND), rnd, trunc));
	}
	if (insn->id != C28X_INS_VASHL32) {
		return NULL;
	}
	RzILOpPure *wide = SHIFTL0(SIGNED(64, VARG(a)), UN(8, n));
	RzILOpBool *ov = INV(EQ(VARL("sw"), SIGNED(64, UNSIGNED(32, VARL("sw")))));
	RzILOpPure *limit = ITE(MSB(VARG(a)), UN(32, 0x80000000), UN(32, 0x7fffffff));
	RzILOpBool *clamp = AND(c28x_vs_bit(C28X_VS_SAT), VARL("so"));
	RzILOpPure *res = ITE(clamp, limit, UNSIGNED(32, VARL("sw")));
	RzILOpBool *ovfr = OR(c28x_vs_bit(C28X_VS_OVFR), VARL("so"));
	RzILOpEffect *flag = c28x_vs_set(C28X_VS_OVFR, ITE(ovfr, UN(8, 1), UN(8, 0)));
	return SEQ4(SETL("sw", wide), SETL("so", ov), flag, SETG(a, res));
}

/**
 * \brief VINC and VDEC VRaL, alone or with a parallel VMOV32 VRb,mem32: VRaL
 * wraps, and no flag changes.
 */
static RzILOpEffect *c28x_vcu_incdec(const C28xInsn *insn) {
	const bool par = insn->nops == 4 && insn->ops[1].kind == C28X_OP_PAR;
	if (insn->nops != 1 && !par) {
		return NULL;
	}
	RzILOpPure *v = c28x_vcu_read(&insn->ops[0]);
	if (!v || insn->ops[0].kind != C28X_OP_REG_LOW) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	RzILOpPure *step = insn->id == C28X_INS_VINC ? ADD(v, UN(16, 1)) : SUB(v, UN(16, 1));
	RzILOpEffect *wr = c28x_vcu_write(&insn->ops[0], step);
	if (!par) {
		return wr;
	}
	RzILOpEffect *load = NULL;
	if (c28x_is_mem(&insn->ops[3])) {
		load = c28x_vcu_write(&insn->ops[2], c28x_ea_load(32));
	}
	if (!wr || !load) {
		rz_il_op_effect_free(wr);
		rz_il_op_effect_free(load);
		return NULL;
	}
	return c28x_with_mem(&insn->ops[3], true, SEQ2(wr, load));
}

/**
 * \brief VBITFLIP reverses VRa's bits, VREVB its bytes.
 */
static RzILOpEffect *c28x_vcu_reverse(const C28xInsn *insn) {
	const char *a = insn->nops == 1 ? c28x_vr_name(&insn->ops[0]) : NULL;
	if (!a) {
		return NULL;
	}
	// swap ever wider neighbouring groups: bits, pairs, nibbles, then bytes and halves
	static const ut32 masks[] = { 0x55555555, 0x33333333, 0x0f0f0f0f, 0x00ff00ff, 0x0000ffff };
	const size_t from = insn->id == C28X_INS_VREVB ? 3 : 0;
	RzILOpEffect *eff = SETL("rv", VARG(a));
	for (size_t i = from; i < RZ_ARRAY_SIZE(masks); i++) {
		const ut32 s = 1U << i;
		RzILOpPure *lo = SHIFTL0(LOGAND(VARL("rv"), UN(32, masks[i])), UN(8, s));
		RzILOpPure *hi = LOGAND(SHIFTR0(VARL("rv"), UN(8, s)), UN(32, masks[i]));
		eff = SEQ2(eff, SETL("rv", LOGOR(lo, hi)));
	}
	return SEQ2(eff, SETG(a, VARL("rv")));
}

static RzILOpEffect *c28x_vcu_nop(RZ_UNUSED const C28xInsn *insn) {
	return NOP();
}

static const C28xVcuLifter c28x_vcu_lifters[] = {
	[C28X_INS_VSETSHL] = c28x_vcu_set,
	[C28X_INS_VSETSHR] = c28x_vcu_set,
	[C28X_INS_VSETK] = c28x_vcu_set,
	[C28X_INS_VSATON] = c28x_vcu_set,
	[C28X_INS_VSATOFF] = c28x_vcu_set,
	[C28X_INS_VRNDON] = c28x_vcu_set,
	[C28X_INS_VRNDOFF] = c28x_vcu_set,
	[C28X_INS_A_VCLROVFI] = c28x_vcu_set,
	[C28X_INS_A_VCLROVFR] = c28x_vcu_set,
	[C28X_INS_VSETCPACK] = c28x_vcu_set,
	[C28X_INS_VCLRCPACK] = c28x_vcu_set,
	[C28X_INS_VSETOPACK] = c28x_vcu_set,
	[C28X_INS_VCLROPACK] = c28x_vcu_set,
	[C28X_INS_VSETCRCMSGFLIP] = c28x_vcu_set,
	[C28X_INS_VCLRCRCMSGFLIP] = c28x_vcu_set,
	[C28X_INS_VCLRDIVE] = c28x_vcu_set,
	[C28X_INS_VCLEAR] = c28x_vcu_clear,
	[C28X_INS_VCLEARALL] = c28x_vcu_clear,
	[C28X_INS_VTCLEAR] = c28x_vcu_clear,
	[C28X_INS_VCRCCLR] = c28x_vcu_clear,
	[C28X_INS_VNOP] = c28x_vcu_nop,
	[C28X_INS_VMOV32] = c28x_vcu_mov,
	[C28X_INS_VMOV16] = c28x_vcu_mov,
	[C28X_INS_VMOVZI] = c28x_vcu_movi,
	[C28X_INS_VMOVXI] = c28x_vcu_movi,
	[C28X_INS_VMOVIX] = c28x_vcu_movi,
	[C28X_INS_VMOVD32] = c28x_vcu_movd32,
	[C28X_INS_VSWAP32] = c28x_vcu_swap,
	[C28X_INS_VXORMOV32] = c28x_vcu_xormov,
	[C28X_INS_VSETCRCSIZE] = c28x_vcu_setcrcsize,
	[C28X_INS_VCRC8L_1] = c28x_vcu_crc,
	[C28X_INS_VCRC8H_1] = c28x_vcu_crc,
	[C28X_INS_VCRC16P1L_1] = c28x_vcu_crc,
	[C28X_INS_VCRC16P1H_1] = c28x_vcu_crc,
	[C28X_INS_VCRC16P2L_1] = c28x_vcu_crc,
	[C28X_INS_VCRC16P2H_1] = c28x_vcu_crc,
	[C28X_INS_VCRC24L_1] = c28x_vcu_crc,
	[C28X_INS_VCRC24H_1] = c28x_vcu_crc,
	[C28X_INS_VCRC32L_1] = c28x_vcu_crc,
	[C28X_INS_VCRC32H_1] = c28x_vcu_crc,
	[C28X_INS_VCRC32P2L_1] = c28x_vcu_crc,
	[C28X_INS_VCRC32P2H_1] = c28x_vcu_crc,
	[C28X_INS_VCRCL] = c28x_vcu_crcgen,
	[C28X_INS_VCRCH] = c28x_vcu_crcgen,
	[C28X_INS_VSWAPCRC] = c28x_vcu_swapcrc,
	[C28X_INS_VLSHL32] = c28x_vcu_shift,
	[C28X_INS_VLSHR32] = c28x_vcu_shift,
	[C28X_INS_VASHL32] = c28x_vcu_shift,
	[C28X_INS_VASHR32] = c28x_vcu_shift,
	[C28X_INS_VINC] = c28x_vcu_incdec,
	[C28X_INS_VDEC] = c28x_vcu_incdec,
	[C28X_INS_VBITFLIP] = c28x_vcu_reverse,
	[C28X_INS_VREVB] = c28x_vcu_reverse,
};

/** \brief Lift the VCU instruction \p insn; NULL while it has no IL yet. */
RZ_IPI RzILOpEffect *c28x_lift_vcu(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if ((size_t)insn->id >= RZ_ARRAY_SIZE(c28x_vcu_lifters) || !c28x_vcu_lifters[insn->id]) {
		return NULL;
	}
	return c28x_vcu_lifters[insn->id](insn);
}
