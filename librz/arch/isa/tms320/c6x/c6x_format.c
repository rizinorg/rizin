// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c6x.h"

// Pure consumer of a decoded C6xInsn: emits the TI-style assembly text. The
// decoder has already resolved every field, so this only concerns syntax.

/**
 * Predicate register named by the creg field (SPRU733 Table 3-9), or NULL for a
 * reserved code. A0 (creg 110) is a C64x+ addition; naming it on older parts is
 * harmless as the encoding is otherwise reserved there.
 */
// Functional units in the order SPMASK's bitmap lists them.
static const char *const c6x_unit_names[8] = { "l1", "l2", "s1", "s2", "d1", "d2", "m1", "m2" };

/**
 * Name of the functional unit selected by \p bit of an SPMASK unit bitmap.
 */
RZ_IPI const char *c6x_unit_name(ut8 bit) {
	return bit < RZ_ARRAY_SIZE(c6x_unit_names) ? c6x_unit_names[bit] : NULL;
}

// Predicate registers by creg code; 0 and 7 are reserved.
static const char *const c6x_pred_regs[8] = { NULL, "b0", "b1", "b2", "a1", "a2", "a0", NULL };

RZ_IPI const char *c6x_pred_reg_name(ut8 creg) {
	return c6x_pred_regs[creg & 7];
}

static void fmt_reg(RzStrBuf *sb, ut8 side, ut8 num) {
	rz_strbuf_appendf(sb, "%c%u", side ? 'b' : 'a', num);
}

// Register pair is written odd:even (high:low), e.g. a1:a0.
static void fmt_regpair(RzStrBuf *sb, ut8 side, ut8 num) {
	char c = side ? 'b' : 'a';
	rz_strbuf_appendf(sb, "%c%u:%c%u", c, (num | 1u), c, (num & ~1u));
}

// Register quad is written high-to-low over four aligned registers, e.g.
// a7:a6:a5:a4 (base is a multiple of four).
static void fmt_regquad(RzStrBuf *sb, ut8 side, ut8 num) {
	char c = side ? 'b' : 'a';
	num &= ~3u;
	rz_strbuf_appendf(sb, "%c%u:%c%u:%c%u:%c%u", c, num + 3, c, num + 2, c, num + 1, c, num);
}

/**
 * Register operand as the disassembly spells it: a single register, a pair
 * odd:even, or a quad counting down from the aligned base. Caller frees.
 */
RZ_IPI RZ_OWN char *c6x_reg_operand_str(const C6xOperand *o) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	switch (o->kind) {
	case C6X_OP_REGPAIR: fmt_regpair(&sb, o->v.reg.side, o->v.reg.num); break;
	case C6X_OP_REGQUAD: fmt_regquad(&sb, o->v.reg.side, o->v.reg.num); break;
	default: fmt_reg(&sb, o->v.reg.side, o->v.reg.num); break;
	}
	return rz_strbuf_drain_nofree(&sb);
}

// Memory operand: base register with the addressing-mode decoration and either a
// register or (scaled) constant offset (SPRU733 Table 3-11).
static void fmt_mem(RzStrBuf *sb, const C6xOperand *o) {
	const char *pre = "", *post = "", *sign = "+";
	bool reg = false;
	switch (o->v.mem.mode) {
	case C6X_AM_NEG_CST: sign = "-"; break;
	case C6X_AM_POS_CST: sign = "+"; break;
	case C6X_AM_NEG_REG: sign = "-", reg = true; break;
	case C6X_AM_POS_REG: sign = "+", reg = true; break;
	case C6X_AM_PREDEC_CST: pre = "--"; break;
	case C6X_AM_PREINC_CST: pre = "++"; break;
	case C6X_AM_POSTDEC_CST: post = "--"; break;
	case C6X_AM_POSTINC_CST: post = "++"; break;
	case C6X_AM_PREDEC_REG: pre = "--", reg = true; break;
	case C6X_AM_PREINC_REG: pre = "++", reg = true; break;
	case C6X_AM_POSTDEC_REG: post = "--", reg = true; break;
	case C6X_AM_POSTINC_REG: post = "++", reg = true; break;
	default: break;
	}
	// plain positive constant offset of zero collapses to *baseR
	bool plain = (o->v.mem.mode == C6X_AM_POS_CST && o->v.mem.off_cst == 0);
	rz_strbuf_append(sb, "*");
	if (pre[0]) {
		rz_strbuf_append(sb, pre);
	} else if (!post[0] && !plain) {
		rz_strbuf_append(sb, sign);
	}
	fmt_reg(sb, o->v.mem.base_side, o->v.mem.base);
	if (post[0]) {
		rz_strbuf_append(sb, post);
	}
	if (plain) {
		return;
	}
	rz_strbuf_append(sb, "[");
	if (reg) {
		fmt_reg(sb, o->v.mem.base_side, o->v.mem.off_reg);
	} else {
		rz_strbuf_appendf(sb, "0x%x", o->v.mem.off_cst);
	}
	rz_strbuf_append(sb, "]");
}

// SPMASK names the units it protects, low bit first, as the assembler spells
// them: "l1,s2". An empty list prints nothing.
static void fmt_unit_list(RzStrBuf *sb, ut8 units) {
	bool first = true;
	for (ut8 u = 0; u < 8; u++) {
		if (!(units & (1u << u))) {
			continue;
		}
		rz_strbuf_appendf(sb, "%s%s", first ? "" : ",", c6x_unit_name(u));
		first = false;
	}
}

static void fmt_operand(RzStrBuf *sb, const C6xInsn *insn, ut64 pc, const C6xOperand *o) {
	switch (o->kind) {
	case C6X_OP_REG:
		fmt_reg(sb, o->v.reg.side, o->v.reg.num);
		break;
	case C6X_OP_REGPAIR:
		fmt_regpair(sb, o->v.reg.side, o->v.reg.num);
		break;
	case C6X_OP_REGQUAD:
		fmt_regquad(sb, o->v.reg.side, o->v.reg.num);
		break;
	case C6X_OP_IMM:
		// Counts read as counts: NOP cycles, bit positions and widths stay
		// decimal. Everything else is a value, so it reads in hex, negative
		// ones signed rather than as a two's-complement pattern.
		if (o->v.imm.decimal || insn->unit == C6X_UNIT_NONE) {
			rz_strbuf_appendf(sb, "%" PFMT64d, (st64)o->v.imm.value);
		} else {
			rz_strbuf_append_signed_hex(sb, (st64)o->v.imm.value);
		}
		break;
	case C6X_OP_CTRLREG:
		rz_strbuf_append(sb, o->v.ctrl ? o->v.ctrl : "?");
		break;
	case C6X_OP_MEM:
		fmt_mem(sb, o);
		break;
	case C6X_OP_UNITMASK:
		fmt_unit_list(sb, o->v.units);
		break;
	case C6X_OP_PCREL:
		// Branch displacements are relative to the fetch-packet base (PCE1),
		// i.e. the address masked to the 32-byte packet, not the instruction.
		rz_strbuf_appendf(sb, "0x%" PFMT64x, (ut64)(c6x_packet_base(pc) + o->v.imm.value));
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

/** Render a decoded instruction to a newly allocated asm string. \p pc is the
 *  instruction address, used to resolve PC-relative branch targets. */
// The fetch-packet header layout field, L7..L1, spelled out as the bit string
// the assembler listing shows.
static void fmt_layout_bits(RzStrBuf *sb, ut32 w) {
	for (int b = 27; b >= 21; b--) {
		rz_strbuf_append(sb, (w >> b) & 1 ? "1" : "0");
	}
}

RZ_IPI RZ_OWN char *c6x_format(const C6xArchDesc *desc, const C6xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(desc && insn, NULL);
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}
	// Compact fetch-packet header (SPRUFE8 3.10.2): render the layout (which
	// of the seven words hold two 16-bit compact instructions) and the
	// expansion field (protection, register set, LD/ST data sizes, branch,
	// saturation). None of the predicate/parallel framing applies here.
	if (insn->is_header) {
		ut32 w = insn->word;
		// Table 3-15: primary/secondary LD/ST data size from DSZ bits 18:16.
		static const char *sec_dsz[8] = { "bu", "b", "hu", "h", "w", "b", "nw", "h" };
		ut8 dsz = (w >> 16) & 0x7;
		rz_strbuf_appendf(sb, ".fphead %s, %s, %s, %s, %s, %s, ",
			(w >> 20) & 1 ? "p" : "n", // PROT: protected loads
			(w >> 19) & 1 ? "h" : "l", // RS: high/low register set
			dsz < 4 ? "w" : "dw", // primary data size
			sec_dsz[dsz], // secondary data size
			(w >> 15) & 1 ? "br" : "nobr", // BR: S-unit compact are branches
			(w >> 14) & 1 ? "sat" : "nosat"); // SAT: compact saturate
		fmt_layout_bits(sb, w);
		rz_strbuf_append(sb, "b");
		return rz_strbuf_drain(sb);
	}
	if (insn->cont) {
		rz_strbuf_append(sb, "|| ");
	}
	const char *pr = c6x_pred_reg_name(insn->creg);
	if (pr) {
		rz_strbuf_appendf(sb, "[%s%s] ", insn->z ? "!" : "", pr);
	}
	if (!insn->mnemonic) {
		rz_strbuf_append(sb, "invalid");
		return rz_strbuf_drain(sb);
	}
	rz_strbuf_append(sb, insn->mnemonic);
	if (insn->unit != C6X_UNIT_NONE) {
		char u = insn->unit == C6X_UNIT_L ? 'l' : insn->unit == C6X_UNIT_S ? 's'
			: insn->unit == C6X_UNIT_M                                 ? 'm'
										   : 'd';
		rz_strbuf_appendf(sb, " .%c%u%s", u, insn->unit_side + 1, insn->cross ? "x" : "");
	}
	for (ut8 i = 0; i < insn->nops; i++) {
		rz_strbuf_append(sb, i == 0 ? " " : ",");
		fmt_operand(sb, insn, pc, &OP(i));
	}
	return rz_strbuf_drain(sb);
}
