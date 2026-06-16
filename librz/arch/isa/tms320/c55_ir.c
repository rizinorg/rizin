// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Shared, arch-independent layer of the TMS320 decode IR (see c55_ir.h):
 *   - c55_decode():        the table-walking decode engine
 *   - c55_x_*():           the operand extractors the per-arch tables reference
 *   - c55_generic_ea() etc: RzIL primitives consumed by each arch's ::lift
 *   - c55_format / c55_fill_analysis / c55_lift: the three pure consumers
 *
 * Per-arch specifics (encoding tables, register set, mnemonic/op-type/lift
 * tables, exotic addressing) live behind a \ref C55ArchDesc; this file only
 * uses that interface, so it is identical for C55x, C55x+ and a future C54x.
 */

#include <rz_analysis.h>
#include <rz_il.h>
#include <string.h>
#include "c55_ir.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// ---------------------------------------------------------------------------
// decode engine
// ---------------------------------------------------------------------------

// Pack the first \p n bytes (<= 8) MSB-first into a word: byte 0 is most
// significant, so a field's bit index counts from the LSB of the instruction.
static ut64 c55_pack(const ut8 *buf, int n) {
	ut64 v = 0;
	for (int i = 0; i < n && i < 8; i++) {
		v = (v << 8) | buf[i];
	}
	return v;
}

// Top-aligned first 4 bytes, the value matched against C55InsnDef::mask/match.
static ut32 c55_head(const ut8 *buf, int len) {
	ut32 h = 0;
	for (int i = 0; i < 4; i++) {
		h = (h << 8) | (ut32)(i < len ? buf[i] : 0);
	}
	return h;
}

static ut64 c55_field(ut64 bits, ut8 lo, ut8 width) {
	if (width == 0 || width >= 64) {
		return bits >> lo;
	}
	return (bits >> lo) & (((ut64)1 << width) - 1);
}

bool c55_decode(const C55ArchDesc *a, const ut8 *buf, int len, C55Insn *out) {
	if (!a || !buf || len <= 0 || !out) {
		return false;
	}
	memset(out, 0, sizeof(*out));
	out->arch = a->arch;
	if (!a->table) {
		return false; // arch decodes via this engine's own front-end, not this engine
	}
	// C54x stores instructions as little-endian 16-bit words; byte-swap each word
	// into a local buffer so the rest of the engine (and the per-arch table) can
	// work in the datasheet's MSB-first order, like the byte-oriented C55x.
	ut8 swapbuf[16];
	if (a->words_le) {
		int n = len < (int)sizeof(swapbuf) ? len : (int)sizeof(swapbuf);
		memcpy(swapbuf, buf, n);
		rz_mem_swap_bytes_2_inplace(swapbuf, n);
		buf = swapbuf;
		if (len > n) {
			len = n;
		}
	}
	// Conditional-execution prefix (C55x+ "if(!TC1)/if(TC1) execute D_Unit",
	// opcodes 0x2e / 0x2f): a one-byte prefix in front of a D-unit instruction.
	// The TI disassembler renders the prefixed instruction identically to the
	// bare one, so when the byte that follows the prefix decodes to a complete
	// instruction through this engine, emit that instruction with its size grown
	// by the prefix byte. (When the following byte does not decode here -- the
	// standalone 0x2e/0x2f encodings such as mmap/lock/linr -- fall through to
	// the normal table walk / legacy front-end.)
	if (a->cond_exec_prefix && len >= 2 && (buf[0] == 0x2e || buf[0] == 0x2f)) {
		C55Insn sub;
		if (c55_decode(a, buf + 1, len - 1, &sub) && sub.size > 0 && 1 + sub.size <= len) {
			*out = sub;
			out->size = sub.size + 1;
			out->cond_exec = true;
			return true;
		}
	}
	// Parallel-pair prefix (C55x+ user-defined parallelism, opcodes 0x30-0x3F): a
	// one-byte prefix whose low nibble is the total byte length of the pair (values
	// below 4 mean 0xF + nibble). The two independent sub-instructions follow,
	// back-to-back, and the TI disassembler renders them joined by " || ". The
	// sub-instructions are re-decoded on demand by the format / lift / analysis
	// consumers from the raw bytes kept here, so no sub-instruction state has to be
	// embedded in C55Insn. (When the two halves do not both decode through this
	// engine, fall through so the legacy front-end can handle the pair.)
	if (a->parallel_prefix && len >= 2 && (buf[0] & 0xf0) == 0x30) {
		ut8 total = buf[0] & 0x0f;
		if (total < 4) {
			total += 0xf;
		}
		if (total <= len && total <= sizeof(out->par_bytes)) {
			C55Insn s1, s2;
			if (c55_decode(a, buf + 1, total - 1, &s1) && s1.size > 0 && 1 + s1.size < total &&
				c55_decode(a, buf + 1 + s1.size, total - 1 - s1.size, &s2) && s2.size > 0 &&
				1 + s1.size + s2.size == total) {
				out->parallel_pair = true;
				out->size = total;
				memcpy(out->par_bytes, buf, total);
				out->par_off1 = 1;
				out->par_off2 = (ut8)(1 + s1.size);
				return true;
			}
		}
	}
	const ut32 head = c55_head(buf, len);
	for (size_t i = 0; i < a->table_len; i++) {
		const C55InsnDef *def = &a->table[i];
		if ((head & def->mask) != def->match) {
			continue;
		}
		int ilen = def->len ? def->len : (a->insn_len ? a->insn_len(buf, len) : 0);
		if (ilen <= 0 || ilen > len) {
			continue;
		}
		out->id = def->id;
		out->lop = def->lop;
		out->square = def->square;
		out->shift16 = def->shift16;
		out->mac_mov = def->mac_mov;
		out->mant_nexp = def->mant_nexp;
		out->mac_store = def->mac_store;
		out->diff_pair = def->diff_pair;
		out->diff_form = def->diff_form;
		out->uns_all = def->uns_all;
		if (def->side_load) {
			out->side_load = true;
		}
		out->both = def->both;
		out->xcc_guard = def->xcc_guard;
		out->quad = def->quad;
		out->size = (ut8)ilen;
		// Parallel-execution marker: in the parallel-capable opcode range bit 0
		// of the leading byte is the "||" flag rather than part of the opcode.
		// A row opts into this by leaving that bit unconstrained in its mask
		// (e.g. 0xfe000000), in which case the bit's value selects the parallel
		// form; rows that pin the bit (0xff000000) treat it as opcode. C54x is
		// word-oriented and has no such bit, so it never carries a parallel flag.
		out->parallel = a->arch != C55_ARCH_C54X && !def->no_parallel && (def->mask & 0x01000000) == 0 && (head & 0x01000000) != 0;
		const ut64 bits = c55_pack(buf, ilen);
		if (def->alt_bit && (c55_field(bits, (ut8)(def->alt_bit - 1), 1) != 0)) {
			// a variant selector beyond the 4-byte match head (e.g. firssub vs
			// firsadd): switch to the alternate id / lift op.
			out->id = def->alt_id;
			out->lop = def->alt_lop;
		}
		if (def->dual && a->fill_dual) {
			// dual "::" MAC: a dedicated filler builds the canonical 6-slot
			// operand layout and the sub-op metadata (the conditional amar1
			// destination assignment does not fit the generic ops[] loop).
			return a->fill_dual(a, bits, def, out);
		}
		// Variant flags packed into def->mods: each 6-bit field holds a bit
		// position (within the packed instruction word) plus one, 0 meaning the
		// flag is absent. Bits 0-5 select the rounding (r) variant, bits 6-11 the
		// memory-MAC side-load (T3=) flag, bits 12-17 the 40-bit (M40) variant,
		// bits 18-23 the fractional (f) variant. Six-bit fields so positions in
		// the wider (5/6-byte) packed words are representable.
		ut8 round_bit = def->mods & 0x3f;
		if (round_bit) {
			out->round = (bits >> (round_bit - 1)) & 1;
		}
		ut8 side_bit = (def->mods >> 6) & 0x3f;
		if (side_bit) {
			out->side_load = (bits >> (side_bit - 1)) & 1;
		}
		ut8 m40_bit = (def->mods >> 12) & 0x3f;
		if (m40_bit) {
			out->m40 = (bits >> (m40_bit - 1)) & 1;
		}
		ut8 fract_bit = (def->mods >> 18) & 0x3f;
		if (fract_bit) {
			out->fract = (bits >> (fract_bit - 1)) & 1;
		}
		ut8 n = 0;
		bool ok = true;
		for (ut8 k = 0; k < C55_MAX_OPS; k++) {
			const C55OpDesc *od = &def->ops[k];
			if (!od->fn) {
				break;
			}
			od->fn(a, bits, od, &out->ops[n]);
			if (out->ops[n].kind == C55_OP_INVALID) {
				// extractor saw an encoding it cannot represent yet:
				// abandon the structured decode so the caller falls
				// back to the legacy front-end.
				ok = false;
				break;
			}
			if (out->ops[n].kind != C55_OP_NONE) {
				n++;
			}
		}
		if (!ok) {
			return false;
		}
		// Instruction-extending memory operand (*arN(#K16) long const-index):
		// the 16-bit constant is a 2-byte extension following the base
		// instruction. It is read big-endian (matching c55_pack), stored as the
		// signed displacement, the size grows by two, and the parallel flag is
		// cleared (the extension occupies the encoding space the "||" bit uses).
		for (ut8 j = 0; j < n; j++) {
			C55AddrMode am = out->ops[j].amode;
			if (am == C55_AM_CONST_IDX || am == C55_AM_CONST_IDX_PRE || am == C55_AM_ABS16) {
				if (ilen + 2 > len) {
					return false;
				}
				ut64 ext = c55_pack(buf + ilen, 2);
				// abs16's k16 is an unsigned page offset; the const-index
				// displacement is a signed offset added to ARn.
				out->ops[j].disp = (am == C55_AM_ABS16)
					? (st32)(ut16)ext
					: (st32)(st16)(ut16)ext;
				out->size = (ut8)(ilen + 2);
				out->parallel = false;
			} else if (am == C55_AM_ABSOLUTE && out->ops[j].abs_addr == C55_ABS_EXT) {
				// Absolute *(#addr): the 24-bit byte address is a 3-byte
				// extension following the base instruction (used by the
				// byte-access mov forms). The extractor marks the pending
				// address with the C55_ABS_EXT sentinel.
				if (ilen + 3 > len) {
					return false;
				}
				out->ops[j].abs_addr = c55_pack(buf + ilen, 3) & 0xffffff;
				out->size = (ut8)(ilen + 3);
				out->parallel = false;
			}
		}
		out->n_ops = n;
		return true;
	}
	return false;
}

// ---------------------------------------------------------------------------
// operand extractors (referenced from the per-arch tables; provisional bodies
// here, tightened against each arch's bit layout when its table is added)
// ---------------------------------------------------------------------------

void c55_x_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.cls = (C55RegClass)d->param;
	out->reg.num = (ut8)c55_field(bits, d->lo, d->width);
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, out->reg.sub) : NULL;
	out->width = ri ? ri->width : 16;
}

void c55_x_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->imm = c55_field(bits, d->lo, d->width);
	out->width = d->width ? d->width : 16;
	out->imm_signed = (d->param & 1) != 0;
	out->reltarget = (d->param & 2) != 0;
	out->addr = (d->param & 4) != 0;
	out->abs_target = (d->param & 8) != 0;
}

void c55_x_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_MEM;
	out->reg.cls = C55_RC_XAR;
	out->reg.num = (ut8)c55_field(bits, d->lo, d->width);
	out->reg.sub = C55_SUB_NONE;
	out->amode = C55_AM_INDIRECT;
	out->access = 16;
}

void c55_x_cond(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_COND;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)c55_field(bits, d->lo, d->width);
	out->reg.sub = C55_SUB_NONE;
	out->relop = (C55Relop)(d->param % 6);
}

// ---------------------------------------------------------------------------
// RzIL primitives
// ---------------------------------------------------------------------------

// VARG of the whole register backing \p r (sub-field slicing is done by callers).
static RzILOpPure *c55_reg_var(const C55ArchDesc *a, C55Reg r) {
	const C55RegInfo *ri = a->reg_info ? a->reg_info(r.cls, r.num, C55_SUB_NONE) : NULL;
	return (ri && ri->il_var) ? VARG(ri->il_var) : NULL;
}

RzILOpPure *c55_generic_ea(const C55ArchDesc *a, const C55Operand *m) {
	if (!a || !m) {
		return NULL;
	}
	const ut32 aw = 24; // C55x byte-address space
	if (m->amode == C55_AM_ABSOLUTE) {
		return UN(aw, m->abs_addr);
	}
	RzILOpPure *ea;
	if (m->amode == C55_AM_ABS16) {
		// abs16(#k16): the data address is DPH:k16 -- the page register supplies
		// the high bits and the unsigned 16-bit constant the low bits.
		ut64 k16 = (ut64)((ut32)m->disp & 0xffff);
		ea = a->mem.page_reg
			? LOGOR(SHIFTL(IL_FALSE, UNSIGNED(aw, VARG(a->mem.page_reg)), UN(8, 16)), UN(aw, k16))
			: UN(aw, k16);
	} else {
		RzILOpPure *base = c55_reg_var(a, m->reg);
		if (!base) {
			return NULL;
		}
		ea = UNSIGNED(aw, base);
		if (m->amode == C55_AM_INDEXED) {
			ea = ADD(ea, SN(aw, m->disp));
		} else if (m->amode == C55_AM_CONST_IDX || m->amode == C55_AM_CONST_IDX_PRE) {
			// *arN(#K16) / *+arN(#K16): ARn is the base, the signed 16-bit
			// constant is the offset. For the plain form ARn is not modified;
			// the pre-modify form additionally writes ARn += K16 via
			// c55_post_effect().
			ea = ADD(ea, SN(aw, m->disp));
		} else if (m->amode == C55_AM_IDXREG) {
			RzILOpPure *idx = c55_reg_var(a, m->index);
			if (idx) {
				ea = ADD(ea, SIGNED(aw, idx));
			}
		}
	}
	// INDIRECT / POST* / PRE* / POSTADD / POSTSUB: EA is the (current) base; the
	// modification is emitted separately by c55_post_effect().
	if (a->mem.addr_unit_log2) {
		ea = MUL(ea, UN(aw, (ut64)1 << a->mem.addr_unit_log2));
	}
	return ea;
}

// EA for any memory operand: generic modes here, exotic modes via the arch hook.
static RzILOpPure *c55_ea(const C55ArchDesc *a, const C55Operand *m) {
	if (m->amode >= C55_AM_INDIRECT && m->amode <= C55_AM_ABS16) {
		return c55_generic_ea(a, m);
	}
	return a->ea ? a->ea(a, m) : NULL;
}

RzILOpPure *c55_read(const C55ArchDesc *a, const C55Operand *op) {
	if (!a || !op) {
		return NULL;
	}
	if (op->kind == C55_OP_IMM) {
		return UN(op->width ? op->width : 16, op->imm);
	}
	if (op->kind == C55_OP_REG) {
		RzILOpPure *v = c55_reg_var(a, op->reg);
		if (!v) {
			return NULL;
		}
		switch (op->reg.sub) {
		case C55_SUB_LO: return CAST(16, IL_FALSE, v);
		case C55_SUB_HI: return CAST(16, IL_FALSE, SHIFTR(IL_FALSE, v, UN(8, 16)));
		case C55_SUB_GUARD: return CAST(8, IL_FALSE, SHIFTR(IL_FALSE, v, UN(8, 32)));
		default: return v;
		}
	}
	if (op->kind == C55_OP_MEM) {
		RzILOpPure *addr = c55_ea(a, op);
		return addr ? LOADW(op->access ? op->access : 16, addr) : NULL;
	}
	return NULL;
}

RzILOpEffect *c55_write(const C55ArchDesc *a, const C55Operand *dst, RzILOpPure *val) {
	if (!a || !dst || !val) {
		rz_il_op_pure_free(val);
		return NULL;
	}
	if (dst->kind == C55_OP_REG) {
		const C55RegInfo *ri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!ri || !ri->il_var) {
			rz_il_op_pure_free(val);
			return NULL;
		}
		if (dst->reg.sub == C55_SUB_NONE) {
			return SETG(ri->il_var, val);
		}
		RzILOpPure *wide = UNSIGNED(ri->width, val); // half read-modify-write
		switch (dst->reg.sub) {
		case C55_SUB_LO:
			return SETG(ri->il_var, LOGOR(LOGAND(VARG(ri->il_var), UN(ri->width, 0xffffff0000ULL)), wide));
		case C55_SUB_HI:
			return SETG(ri->il_var, LOGOR(LOGAND(VARG(ri->il_var), UN(ri->width, 0xff0000ffffULL)), SHIFTL(IL_FALSE, wide, UN(8, 16))));
		case C55_SUB_GUARD:
			return SETG(ri->il_var, LOGOR(LOGAND(VARG(ri->il_var), UN(ri->width, 0x00ffffffffULL)), SHIFTL(IL_FALSE, LOGAND(wide, UN(ri->width, 0xff)), UN(8, 32))));
		default:
			return SETG(ri->il_var, wide);
		}
	}
	if (dst->kind == C55_OP_MEM) {
		RzILOpPure *addr = c55_ea(a, dst);
		if (!addr) {
			rz_il_op_pure_free(val);
			return NULL;
		}
		return STOREW(addr, val);
	}
	rz_il_op_pure_free(val);
	return NULL;
}

// Write a 16-bit arithmetic result into an accumulator half per the C55x+
// accumulator-access rules (SWPU104 1.5.1): a .L destination updates only
// ACx[15:0]; a .H destination updates ACx[39:16], sign-extending the 16-bit
// result through the guard bits. (Copy/move into .H instead writes ACx[31:16]
// and is handled by c55_write.) res16 must be a 16-bit value.
static RzILOpEffect *c55_write_half_arith(const C55ArchDesc *a, const C55Operand *dst, RzILOpPure *res16) {
	const C55RegInfo *ri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
	if (!ri || !ri->il_var || ri->width < 40) {
		rz_il_op_pure_free(res16);
		return NULL;
	}
	if (dst->reg.sub == C55_SUB_HI) {
		// ACx[39:16] = sign-extend(res16); preserve ACx[15:0].
		return SETG(ri->il_var,
			LOGOR(LOGAND(VARG(ri->il_var), UN(ri->width, 0xffff)),
				SHIFTL(IL_FALSE, SIGNED(ri->width, res16), UN(8, 16))));
	}
	// .L: ACx[15:0] = res16; preserve ACx[39:16].
	return SETG(ri->il_var,
		LOGOR(LOGAND(VARG(ri->il_var), UN(ri->width, 0xffffff0000ULL)), UNSIGNED(ri->width, res16)));
}

RzILOpEffect *c55_post_effect(const C55ArchDesc *a, const C55Operand *m) {
	if (!a || !m) {
		return NULL;
	}
	const C55RegInfo *ri = a->reg_info ? a->reg_info(m->reg.cls, m->reg.num, C55_SUB_NONE) : NULL;
	if (!ri || !ri->il_var) {
		return NULL;
	}
	const ut32 pw = a->mem.ptr_width ? a->mem.ptr_width : 23;
	switch (m->amode) {
	case C55_AM_POSTINC: return SETG(ri->il_var, ADD(VARG(ri->il_var), UN(pw, 1)));
	case C55_AM_POSTDEC: return SETG(ri->il_var, SUB(VARG(ri->il_var), UN(pw, 1)));
	case C55_AM_POSTADD: {
		RzILOpPure *idx = c55_reg_var(a, m->index);
		return idx ? SETG(ri->il_var, ADD(VARG(ri->il_var), SIGNED(pw, idx))) : NULL;
	}
	case C55_AM_POSTSUB: {
		RzILOpPure *idx = c55_reg_var(a, m->index);
		return idx ? SETG(ri->il_var, SUB(VARG(ri->il_var), SIGNED(pw, idx))) : NULL;
	}
	case C55_AM_CONST_IDX_PRE:
		// *+arN(#K16): pre-modify writes the signed constant back into ARn.
		return SETG(ri->il_var, ADD(VARG(ri->il_var), SN(pw, m->disp)));
	default: return NULL;
	}
}

// ---------------------------------------------------------------------------
// consumers
// ---------------------------------------------------------------------------

// Resolve a PC-relative branch/call target: next-instruction address plus the
// sign-extended offset carried by the address-style immediate operand (its
// width sets the sign bit). Shared by the analysis and lifter consumers.
static ut64 c55_branch_target(const C55Insn *insn, ut64 pc) {
	for (ut8 i = 0; i < insn->n_ops; i++) {
		const C55Operand *o = &insn->ops[i];
		if (o->kind == C55_OP_IMM && (o->addr || o->reltarget)) {
			ut32 w = o->width ? o->width : 16;
			ut64 v = o->imm;
			if (o->abs_target) {
				// Absolute target: the operand is the destination address
				// itself (24-bit program space), not a pc-relative offset.
				return v & 0xffffff;
			}
			st64 soff = o->reltarget_unsigned
				? (st64)v
				: ((w < 64 && (v & ((ut64)1 << (w - 1)))) ? (st64)(v - ((ut64)1 << w)) : (st64)v);
			return pc + insn->size + soff;
		}
	}
	return pc + insn->size;
}

/* The instruction id alone can be ambiguous for control transfers: 'b' and
 * 'call' cover both a register-indirect form (target in a register) and a
 * direct form (a pc-relative or absolute immediate target). Refine the
 * op_type by operand kind so a direct target reports as JMP/CALL while a
 * register operand keeps the register-indirect UJMP/UCALL. */
static ut32 c55_effective_type(const C55ArchDesc *a, const C55Insn *insn) {
	ut32 type = a->op_type ? a->op_type(insn->id) : RZ_ANALYSIS_OP_TYPE_NULL;
	if (insn->n_ops >= 1 && insn->ops[0].kind == C55_OP_IMM) {
		if (type == RZ_ANALYSIS_OP_TYPE_UJMP) {
			type = RZ_ANALYSIS_OP_TYPE_JMP;
		} else if (type == RZ_ANALYSIS_OP_TYPE_UCALL) {
			type = RZ_ANALYSIS_OP_TYPE_CALL;
		}
	} else if (insn->n_ops >= 1 && insn->ops[0].kind == C55_OP_REG) {
		// A register operand makes a branch / call register-indirect (b ACx /
		// call ACx); refine the resolved direct type to its indirect form.
		if (type == RZ_ANALYSIS_OP_TYPE_JMP) {
			type = RZ_ANALYSIS_OP_TYPE_UJMP;
		} else if (type == RZ_ANALYSIS_OP_TYPE_CALL) {
			type = RZ_ANALYSIS_OP_TYPE_UCALL;
		}
	}
	return type;
}

// PSH / POP move one stack word for a 16-bit operand and two for a 32-bit
// (accumulator / dbl) operand. On C55x the magnitude follows the operand's
// width, so a 16-bit register push moves a single word; C55x+ stores a full
// 32-bit (two-word) slot for every register push. A memory operand moves one
// word, or two when doubled. A form with no register or memory operand (a
// dual-register push-pop) moves two words.
static st32 c55_stack_words(const C55ArchDesc *a, const C55Insn *insn) {
	if (insn->both && insn->n_ops >= 2) {
		// Dual-register psh/pop (0x38/0x3a): two gr4 registers are pushed/popped
		// in one instruction. The legacy decoder records a fixed single-word SP
		// delta here regardless of the operand widths, so reproduce that. (The
		// pshboth/popboth pair form has a single operand and keeps the width-
		// based count below.)
		return 1;
	}
	for (ut8 i = 0; i < insn->n_ops; i++) {
		if (insn->ops[i].kind == C55_OP_MEM) {
			return insn->ops[i].dbl ? 2 : 1;
		}
		if (insn->ops[i].kind == C55_OP_REG) {
			if (a->arch == C55_ARCH_C55X && !insn->ops[i].dbl && insn->ops[i].width <= 16) {
				return 1;
			}
			return 2;
		}
	}
	return 2;
}

void c55_fill_analysis(const C55ArchDesc *a, const C55Insn *insn, RzAnalysisOp *op) {
	if (!a || !insn || !op) {
		return;
	}
	op->id = insn->id;
	if (insn->parallel_pair) {
		// "||" parallel pair: report the combined size and take the analysis op
		// type from the first sub-instruction (the legacy decoder likewise types
		// the pair by its leading instruction).
		op->size = insn->size;
		C55Insn s1;
		if (c55_decode(a, insn->par_bytes + insn->par_off1, insn->size - insn->par_off1, &s1)) {
			op->type = c55_effective_type(a, &s1);
		}
		return;
	}
	op->size = insn->size;
	ut32 type = c55_effective_type(a, insn);
	op->type = type;
	switch (type) {
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_JMP: {
		op->jump = c55_branch_target(insn, op->addr);
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		if (type == RZ_ANALYSIS_OP_TYPE_JMP) {
			op->eob = true;
		} else {
			op->fail = op->addr + insn->size;
		}
		if (type == RZ_ANALYSIS_OP_TYPE_CALL || type == RZ_ANALYSIS_OP_TYPE_CCALL) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = 2;
		}
		break;
	}
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL: {
		// Register-indirect branch / call: the target lives in a register, so
		// there is no static jump address to record. Expose the indirect
		// register and the fall-through address; an indirect call additionally
		// adjusts the stack pointer by the return-address slot.
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		op->fail = op->addr + insn->size;
		if (insn->n_ops >= 1 && insn->ops[0].kind == C55_OP_REG && a->reg_info) {
			const C55RegInfo *ri = a->reg_info(insn->ops[0].reg.cls, insn->ops[0].reg.num, insn->ops[0].reg.sub);
			if (ri) {
				op->ireg = ri->name;
			}
		}
		if (type == RZ_ANALYSIS_OP_TYPE_UCALL) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = 2;
		}
		break;
	}
	case RZ_ANALYSIS_OP_TYPE_SWI:
	case RZ_ANALYSIS_OP_TYPE_TRAP:
		// Software interrupt / trap to a vector number: expose the vector as
		// the op value when the instruction carries one (reset, also a trap,
		// has no operand and leaves the value unset).
		if (insn->n_ops >= 1 && insn->ops[0].kind == C55_OP_IMM) {
			op->val = insn->ops[0].imm;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_RET:
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -2;
		// The C55x return leaves the destination-register field unset; the
		// C55x+ convention marks the stack pointer as the affected register.
		if (a->arch != C55_ARCH_C55X) {
			op->reg = "sp";
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_CRET:
		// Conditional return: pops the return address like RET when taken, but
		// keeps a fall-through edge instead of ending the block.
		op->fail = op->addr + insn->size;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -2;
		// As with RET, the C55x+ convention marks the stack pointer as the
		// affected register.
		if (a->arch != C55_ARCH_C55X) {
			op->reg = "sp";
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_PUSH:
	case RZ_ANALYSIS_OP_TYPE_UPUSH:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = c55_stack_words(a, insn);
		op->reg = "sp";
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case RZ_ANALYSIS_OP_TYPE_POP:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -c55_stack_words(a, insn);
		op->reg = "sp";
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
		// aadd #k8, sp (frame setup): the immediate prints unsigned but is a
		// signed 8-bit constant, and the stack grows toward lower addresses, so
		// the recorded SP delta is the negation of the (signed) amount added.
		if (insn->n_ops == 2 && insn->ops[0].kind == C55_OP_IMM &&
			insn->ops[1].kind == C55_OP_REG && insn->ops[1].reg.cls == C55_RC_SP) {
			st32 k = (st8)(ut8)insn->ops[0].imm;
			op->val = k;
			op->disp = k;
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = (type == RZ_ANALYSIS_OP_TYPE_ADD) ? -k : k;
			op->reg = "sp";
		} else if (insn->n_ops == 2 && insn->ops[0].kind == C55_OP_REG &&
			insn->ops[1].kind == C55_OP_REG && a->reg_info &&
			(insn->lop == C55_LOP_AREG_ADD || insn->lop == C55_LOP_AREG_SUB)) {
			// Register-to-register address arithmetic (aadd / asub ACx, ARy):
			// expose the destination as the affected register and the source as
			// the index register.
			const C55RegInfo *dri = a->reg_info(insn->ops[1].reg.cls, insn->ops[1].reg.num, C55_SUB_NONE);
			const C55RegInfo *sri = a->reg_info(insn->ops[0].reg.cls, insn->ops[0].reg.num, C55_SUB_NONE);
			if (dri) {
				op->reg = dri->name;
			}
			if (sri) {
				op->ireg = sri->name;
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_STORE:
	case RZ_ANALYSIS_OP_TYPE_MOV: {
		// Single data-memory load / store: expose the register operand, the
		// addressing base register, the displacement, the access direction and
		// the referenced-data size. A register-to-register or immediate move
		// has no memory operand and falls through without setting these.
		// A single memory operand with no register (delay Smem: a memory-to-
		// memory word move) still records the access width and write direction.
		// The C55x `mov` family is typed MOV; the C54x ld/st family is typed
		// LOAD/STORE - both reach this block and use the same operand layout
		// (the data-memory operand and the register operand, source first).
		if (insn->n_ops == 1 && insn->ops[0].kind == C55_OP_MEM) {
			const C55Operand *mem = &insn->ops[0];
			op->refptr = (mem->access ? mem->access : 16) / 8;
			op->ptrsize = op->refptr;
			op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
			break;
		}
		if (insn->n_ops < 2 || !a->reg_info) {
			break;
		}
		const C55Operand *o0 = &insn->ops[0];
		const C55Operand *o1 = &insn->ops[1];
		const C55Operand *mem = NULL;
		const C55Operand *reg = NULL;
		bool load = false;
		if (o0->kind == C55_OP_MEM && o1->kind == C55_OP_REG) {
			mem = o0;
			reg = o1;
			load = true;
		} else if (o1->kind == C55_OP_MEM && o0->kind == C55_OP_REG) {
			mem = o1;
			reg = o0;
		} else {
			break;
		}
		const C55RegInfo *rri = a->reg_info(reg->reg.cls, reg->reg.num, C55_SUB_NONE);
		if (rri) {
			op->reg = rri->name;
		}
		const C55RegInfo *bri = a->reg_info(mem->reg.cls, mem->reg.num, C55_SUB_NONE);
		if (bri) {
			op->ireg = bri->name;
		}
		if (mem->amode == C55_AM_INDEXED ||
			(a->arch == C55_ARCH_C54X && mem->amode == C55_AM_DIRECT)) {
			// indexed *ar(disp); or C54x direct @dma (a DP/SP-relative offset)
			op->disp = mem->disp;
		}
		op->direction = load ? RZ_ANALYSIS_OP_DIR_READ : RZ_ANALYSIS_OP_DIR_WRITE;
		if (load) {
			op->refptr = (mem->access ? mem->access : 16) / 8;
		}
		break;
	}
	default:
		break;
	}
	// Generic immediate-value exposure: record the first *data* immediate (one
	// that is not a branch/call target) on op->val so callers that look for the
	// constant involved in an operation (add/sub/and/or/xor/cmp/mov #k, ...)
	// can find it. A more specific case above (the swi vector, the frame
	// adjustment) may already have set op->val, in which case it is kept.
	// (op->val defaults to UT64_MAX -- the "unset" sentinel -- not 0.)
	if (op->val == UT64_MAX) {
		for (ut8 i = 0; i < insn->n_ops; i++) {
			const C55Operand *o = &insn->ops[i];
			if (o->kind == C55_OP_IMM && !o->addr && !o->reltarget) {
				op->val = o->imm;
				break;
			}
		}
	}
}

// Build the IL predicate for a register-compare branch condition (reg <relop>
// imm|0). Status-flag and register-to-register compares return NULL so the
// per-arch lifter handles them. The compare constant takes the subject's width.
static RzILOpPure *c55_cmp_pred(const C55ArchDesc *a, const C55Operand *c, bool uns); // reg-reg compare predicate (defined below)
static RzILOpPure *c55_cond_pred(const C55ArchDesc *a, const C55Operand *c, bool uns) {
	if (c->cond_is_flag) {
		// The single-bit st0_55 status flags (tc1, tc2, carry and their
		// negations) share the same bit layout on both C55x and C55x+, so the
		// shared predicate covers both. The overflow flags and the boolean
		// combinations are not modelled (NULL -> the per-arch lifter handles
		// them); only the flag ids enumerated below are lifted here.
		ut8 bit;
		bool neg = false;
		switch (c->cond_flag) {
		case 4: bit = 13; break; // tc1
		case 5: bit = 12; break; // tc2
		case 6: bit = 11; break; // carry
		case 20:
			bit = 13;
			neg = true;
			break; // !tc1
		case 21:
			bit = 12;
			neg = true;
			break; // !tc2
		case 22:
			bit = 11;
			neg = true;
			break; // !carry
		default: return NULL;
		}
		RzILOpBool *p = LSB(SHIFTR(IL_FALSE, VARG("st0_55"), UN(4, (ut64)bit)));
		return neg ? INV(p) : p;
	}
	if (c->cmp_to_reg) {
		// register-register compare-and-branch (bccu Ra <relop> Rb): reuse the
		// shared cmp predicate builder (same relop/uns/sub-register handling as
		// the cmp/cmpand/cmpor instructions).
		return c55_cmp_pred(a, c, uns);
	}
	const C55RegInfo *ri = a->reg_info ? a->reg_info(c->reg.cls, c->reg.num, C55_SUB_NONE) : NULL;
	if (!ri || !ri->il_var) {
		return NULL;
	}
	// An accumulator-half operand (ACx.h / ACx.l) compares the 16-bit
	// sub-register, not the full accumulator: read it through c55_read (which
	// applies the .h >> 16 / .l low-word extraction) and compare at 16 bits.
	// Full registers (sub == NONE) keep the register width. This sub-register
	// path is only reachable on C55x+, whose cond-imm extractor sets reg.sub;
	// the C55x extractor never does, so C55x behaviour is unchanged.
	bool half = c->reg.sub == C55_SUB_HI || c->reg.sub == C55_SUB_LO;
	ut8 w = half ? 16 : ri->width;
	ut64 k = c->imm;
	C55Operand regop = { 0 };
	regop.kind = C55_OP_REG;
	regop.reg = c->reg;
#define CONDV() (half ? c55_read(a, &regop) : VARG(ri->il_var))
	// 'bccu' compares unsigned: the ordered relops use ule rather than sle.
	// Equality is sign-agnostic. C55x cond-imm branches are always signed
	// (uns == false), so their comparisons are unchanged.
#define LEQ(x, y) (uns ? ULE((x), (y)) : SLE((x), (y)))
	switch (c->relop) {
	case C55_REL_EQ: return EQ(CONDV(), UN(w, k));
	case C55_REL_NE: return INV(EQ(CONDV(), UN(w, k)));
	case C55_REL_LT: return AND(LEQ(CONDV(), UN(w, k)), INV(EQ(CONDV(), UN(w, k))));
	case C55_REL_LE: return LEQ(CONDV(), UN(w, k));
	case C55_REL_GT: return INV(LEQ(CONDV(), UN(w, k)));
	case C55_REL_GE: return INV(AND(LEQ(CONDV(), UN(w, k)), INV(EQ(CONDV(), UN(w, k)))));
	default: return NULL;
	}
#undef LEQ
#undef CONDV
}

// One operand of a register-register compare (cmp/cmpand/cmpor), promoted to
// the comparison width `tw` (the wider of the two operands): a narrower operand
// is sign- or zero-extended per the unsigned flag; an operand already `tw` bits
// wide is taken as-is. An accumulator-half operand (ACx.h / ACx.l, only seen on
// C55x+) is read as its 16-bit value through c55_read.
static RzILOpPure *c55_cmp_regval(const C55ArchDesc *a, const C55Reg *r, bool uns, ut8 tw) {
	bool half = r->sub == C55_SUB_HI || r->sub == C55_SUB_LO;
	ut8 rw;
	RzILOpPure *v;
	if (half) {
		C55Operand regop = { 0 };
		regop.kind = C55_OP_REG;
		regop.reg = *r;
		v = c55_read(a, &regop); // 16-bit half (.l low word / .h bits 31..16)
		rw = 16;
	} else {
		const C55RegInfo *ri = a->reg_info ? a->reg_info(r->cls, r->num, C55_SUB_NONE) : NULL;
		if (!ri || !ri->il_var) {
			return NULL;
		}
		v = VARG(ri->il_var);
		rw = ri->width;
	}
	if (rw < tw) {
		v = uns ? UNSIGNED(tw, v) : SIGNED(tw, v);
	}
	return v;
}

// The width of one compare operand: a sub-register half is 16 bits, otherwise
// the register's own width.
static ut8 c55_cmp_opwidth(const C55ArchDesc *a, const C55Reg *r) {
	if (r->sub == C55_SUB_HI || r->sub == C55_SUB_LO) {
		return 16;
	}
	const C55RegInfo *ri = a->reg_info ? a->reg_info(r->cls, r->num, C55_SUB_NONE) : NULL;
	return ri ? ri->width : 0;
}

// The comparison width of a register-register compare: the wider of the two
// operand registers (T/AR-vs-T/AR or half-vs-half compare at 16 bits, anything
// against a full accumulator at 40).
static ut8 c55_cmp_width(const C55ArchDesc *a, const C55Operand *c) {
	ut8 sw = c55_cmp_opwidth(a, &c->reg);
	ut8 dw = c55_cmp_opwidth(a, &c->index);
	return sw > dw ? sw : dw;
}

// Build the boolean predicate (SRC <relop> DST) for a register-register compare.
// `c` is the COND operand: c->reg is SRC, c->index is DST. Each operand value is
// rebuilt for every use (RzIL pures are not shared).
static RzILOpPure *c55_cmp_pred(const C55ArchDesc *a, const C55Operand *c, bool uns) {
	ut8 tw = c55_cmp_width(a, c);
	switch (c->relop) {
	case C55_REL_EQ: return EQ(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw));
	case C55_REL_NE: return INV(EQ(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw)));
	case C55_REL_LT: {
		RzILOpPure *le = uns ? ULE(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw))
				     : SLE(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw));
		return AND(le, INV(EQ(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw))));
	}
	case C55_REL_GE: {
		RzILOpPure *le = uns ? ULE(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw))
				     : SLE(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw));
		return INV(AND(le, INV(EQ(c55_cmp_regval(a, &c->reg, uns, tw), c55_cmp_regval(a, &c->index, uns, tw)))));
	}
	default: return NULL;
	}
}

// Lift a C55x+ single-data-memory move for the register-indirect modes. The
// Smem base is an ARn for display, but the address pointer is the 23-bit XARn,
// so the base register is promoted before the address is formed. The address,
// memory access and post-modify are produced by the shared EA primitives.
// Pre-modify (*+ar / *-ar) addressing is left to the per-arch lifter for now,
// since the shared post-modify primitive does not model it.
static RzILOpEffect *c55_mem_move(const C55ArchDesc *a, const C55Operand *reg, const C55Operand *mem, bool load) {
	if (mem->shamt) {
		// A shifted memory access (mov Smem << #SHIFT, ACx) is not lifted yet;
		// the legacy decoder leaves it without IL, so do the same here.
		return NULL;
	}
	if (mem->sh_mem_reg_set || mem->mem_round) {
		// A register-shifted (Smem << Tx) or rounded (rnd(...)) memory access is
		// likewise left without IL, matching the legacy decoder.
		return NULL;
	}
	if (mem->byte_sel == 1 || mem->byte_sel == 2) {
		// high_byte()/low_byte() accesses are left without IL, matching the
		// legacy decoder; only the plain byte() form (byte_sel 3) is lifted.
		return NULL;
	}
	if (mem->byte_sel == 3) {
		// Plain byte() access: an 8-bit load/store. On load the byte is
		// sign-/zero-extended to a 16-bit word and then written through the
		// destination (a half-register write merges it via read-modify-write);
		// on store the source is truncated to its low 8 bits. The data address
		// is computed exactly as for a word access (the byte-vs-word width only
		// affects loadw/storew, not the effective address).
		switch (mem->amode) {
		case C55_AM_INDIRECT:
		case C55_AM_POSTINC:
		case C55_AM_POSTDEC:
		case C55_AM_IDXREG:
		case C55_AM_POSTADD:
		case C55_AM_POSTSUB:
		case C55_AM_INDEXED:
		case C55_AM_ABSOLUTE:
		case C55_AM_CONST_IDX:
		case C55_AM_CONST_IDX_PRE:
		case C55_AM_ABS16:
			break;
		default:
			return NULL;
		}
		C55Operand bm = *mem;
		if (bm.reg.cls == C55_RC_AR) {
			bm.reg.cls = C55_RC_XAR;
		}
		bm.access = 8;
		if (load) {
			const C55RegInfo *dri = a->reg_info ? a->reg_info(reg->reg.cls, reg->reg.num, C55_SUB_NONE) : NULL;
			if (!dri || !dri->il_var) {
				return NULL;
			}
			RzILOpPure *v = c55_read(a, &bm); // loadw 0 8
			if (!v) {
				return NULL;
			}
			if (reg->reg.sub == C55_SUB_NONE) {
				// whole-register destination: extend the byte straight to the
				// register width (ac -> 40, ar -> 16).
				v = bm.uns ? UNSIGNED(dri->width, v) : SIGNED(dri->width, v);
			} else {
				// half-register destination: extend to a 16-bit word; c55_write
				// then merges it into the accumulator via read-modify-write.
				v = bm.uns ? UNSIGNED(16, v) : SIGNED(16, v);
			}
			RzILOpEffect *wr = c55_write(a, reg, v);
			if (!wr) {
				return NULL;
			}
			RzILOpEffect *post = c55_post_effect(a, &bm);
			return post ? SEQ2(wr, post) : wr;
		}
		RzILOpPure *v = c55_read(a, reg);
		if (!v) {
			return NULL;
		}
		v = UNSIGNED(8, v); // store the low byte of the source
		RzILOpEffect *wr = c55_write(a, &bm, v);
		if (!wr) {
			return NULL;
		}
		RzILOpEffect *post = c55_post_effect(a, &bm);
		return post ? SEQ2(wr, post) : wr;
	}
	switch (mem->amode) {
	case C55_AM_INDIRECT:
	case C55_AM_POSTINC:
	case C55_AM_POSTDEC:
	case C55_AM_IDXREG:
	case C55_AM_POSTADD:
	case C55_AM_POSTSUB:
	case C55_AM_INDEXED:
	case C55_AM_ABSOLUTE:
	case C55_AM_CONST_IDX:
	case C55_AM_CONST_IDX_PRE:
	case C55_AM_ABS16:
		break;
	default:
		return NULL; // pre-modify (PRE*) and exotic modes -> per-arch lifter
	}
	C55Operand m = *mem;
	if (m.reg.cls == C55_RC_AR) {
		m.reg.cls = C55_RC_XAR; // ARn is the low half of the XARn pointer
	}
	if (load) {
		const C55RegInfo *dri = a->reg_info ? a->reg_info(reg->reg.cls, reg->reg.num, C55_SUB_NONE) : NULL;
		if (!dri || !dri->il_var) {
			return NULL;
		}
		RzILOpPure *v = c55_read(a, &m);
		if (!v) {
			return NULL;
		}
		ut32 lw = m.access ? m.access : 16;
		if (reg->reg.sub == C55_SUB_LO || reg->reg.sub == C55_SUB_HI) {
			// Half-register destination (mov Smem, ACx.l / ACx.h): the loaded
			// word is merged into the accumulator half by c55_write's
			// read-modify-write; a wider memory access is first narrowed to the
			// 16-bit half width.
			if (lw > 16) {
				v = UNSIGNED(16, v);
			}
		} else if (dri->width > lw) {
			// mov Smem, ACx sign-extends; the uns() qualifier zero-extends.
			v = m.uns ? UNSIGNED(dri->width, v) : SIGNED(dri->width, v);
		} else if (dri->width < lw) {
			// a narrow destination register (e.g. the 7-bit dph or 9-bit pdp
			// targeted by the mov Smem, <special-reg> forms) truncates the
			// loaded word down to its width.
			v = UNSIGNED(dri->width, v);
		}
		RzILOpEffect *wr = c55_write(a, reg, v);
		if (!wr) {
			return NULL;
		}
		RzILOpEffect *post = c55_post_effect(a, &m);
		return post ? SEQ2(wr, post) : wr;
	}
	RzILOpPure *v = c55_read(a, reg); // half / register source
	if (!v) {
		return NULL;
	}
	if (reg->reg.sub == C55_SUB_NONE) {
		// A whole-register source wider than the memory access (e.g. a 40-bit
		// accumulator stored to a 16-bit word) is truncated to the access
		// width; a narrower source (e.g. a 23-bit XARn stored as a 32-bit
		// double word) is zero-extended up to it; a half source is already the
		// right width.
		const C55RegInfo *sri = a->reg_info ? a->reg_info(reg->reg.cls, reg->reg.num, C55_SUB_NONE) : NULL;
		ut32 sw = m.access ? m.access : 16;
		if (sri && sri->width != sw) {
			v = UNSIGNED(sw, v);
		}
	}
	RzILOpEffect *wr = c55_write(a, &m, v);
	if (!wr) {
		return NULL;
	}
	RzILOpEffect *post = c55_post_effect(a, &m);
	return post ? SEQ2(wr, post) : wr;
}

// A multiplicand for the multiply family, sign-extended (or, under the uns
// qualifier, zero-extended) to the 40-bit product width: a 16-bit register
// (Tx) is taken directly, a 40-bit accumulator contributes its high word
// (ACx(32-16), sign-extended), and a memory operand is the loaded word. A memory
// operand is assumed
// already promoted to its address-pointer register class (ARn -> XARn) by the
// caller. Returns NULL for operand shapes that are not valid multiplicands.
static RzILOpPure *c55_mul_val(const C55ArchDesc *a, const C55Operand *op) {
	if (op->kind == C55_OP_MEM) {
		RzILOpPure *l = c55_read(a, op);
		if (!l) {
			return NULL;
		}
		return op->uns ? UNSIGNED(40, l) : SIGNED(40, l);
	}
	const C55RegInfo *ri = a->reg_info ? a->reg_info(op->reg.cls, op->reg.num, C55_SUB_NONE) : NULL;
	if (!ri || !ri->il_var) {
		return NULL;
	}
	if (ri->width == 16) {
		return op->uns ? UNSIGNED(40, VARG(ri->il_var)) : SIGNED(40, VARG(ri->il_var));
	}
	if (ri->width == 40) {
		// An accumulator feeds the multiplier as ACx(32-16) -- the high word,
		// sign-extended -- not its low half. This holds for the register multiply
		// (MPY/MAC ACx, Tx), the memory MAC (Smem * ACx) and the FIRS pair; see
		// spru374g. Modeled as the sign-extended bits 31-16, matching c55_read's
		// C55_SUB_HI reader.
		return SIGNED(40, CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(ri->il_var), UN(8, 16))));
	}
	return NULL;
}

// Build the RzIL effect for one multiply / multiply-accumulate / multiply-subtract.
// `ops` points at this operation's operands: m1 first, the destination accumulator
// last; the three-operand memory MAC adds Cmem in the middle, the four-operand
// register form (mac{m} Smem, Tx, ACx, ACy) carries an explicit accumulator source
// in ops[2], and the three-operand square form keeps the accumulator source in
// ops[1]. `lop` selects plain multiply (NONE), accumulate (MAC) or subtract (MAS);
// `shift16` shifts the accumulator right by 16 before accumulating (the dual-MAC
// ">> #16" form); `square` multiplies the first multiplicand by itself; `side_load`
// also writes the loaded Smem word into T3. Memory post-modify side effects are
// applied after the write, in operand order. Returns NULL if the operands are not a
// shape this builder represents.
static RzILOpEffect *c55_mac_effect(const C55ArchDesc *a, const C55Operand *ops, ut8 n_ops,
	C55LiftOp lop, bool round, bool shift16, bool square, bool side_load) {
	if (n_ops < 2 || n_ops > 4) {
		return NULL;
	}
	const C55Operand *m1 = &ops[0];
	const C55Operand *dst = &ops[n_ops - 1];
	const C55Operand *m2, *acc;
	if (square) {
		m2 = m1;
		acc = (n_ops == 3) ? &ops[1] : dst;
	} else {
		m2 = (n_ops == 2) ? dst : &ops[1];
		acc = (n_ops == 4) ? &ops[2] : dst;
	}
	if (dst->kind != C55_OP_REG || dst->reg.sub != C55_SUB_NONE) {
		return NULL;
	}
	const C55Operand *mul[2] = { m1, m2 };
	for (int i = 0; i < 2; i++) {
		const C55Operand *o = mul[i];
		bool reg_ok = o->kind == C55_OP_REG && o->reg.sub == C55_SUB_NONE &&
			!o->shamt && !o->sh_left && !o->sh_by_reg;
		if (!reg_ok && o->kind != C55_OP_MEM) {
			return NULL;
		}
	}
	const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
	if (!dri || !dri->il_var || dri->width != 40) {
		return NULL;
	}
	const C55RegInfo *ari = a->reg_info ? a->reg_info(acc->reg.cls, acc->reg.num, C55_SUB_NONE) : NULL;
	if (acc->kind != C55_OP_REG || acc->reg.sub != C55_SUB_NONE || !ari || !ari->il_var || ari->width != 40) {
		return NULL;
	}
	C55Operand m1p = *m1, m2p = *m2;
	if (m1p.kind == C55_OP_MEM && m1p.reg.cls == C55_RC_AR) {
		m1p.reg.cls = C55_RC_XAR;
	}
	if (m2p.kind == C55_OP_MEM && m2p.reg.cls == C55_RC_AR) {
		m2p.reg.cls = C55_RC_XAR;
	}
	RzILOpPure *v1 = c55_mul_val(a, &m1p);
	RzILOpPure *v2 = c55_mul_val(a, &m2p);
	if (!v1 || !v2) {
		rz_il_op_pure_free(v1);
		rz_il_op_pure_free(v2);
		return NULL;
	}
	RzILOpPure *val = MUL(v1, v2);
	if (lop == C55_LOP_MAC || lop == C55_LOP_MAS) {
		// the ">> #16" form shifts the accumulator right by 16 (arithmetic,
		// 40-bit) before the product is accumulated.
		RzILOpPure *acc_term = shift16
			? SHIFTR(MSB(VARG(ari->il_var)), VARG(ari->il_var), UN(6, 16))
			: VARG(ari->il_var);
		val = (lop == C55_LOP_MAC) ? ADD(acc_term, val) : SUB(acc_term, val);
	}
	if (round) {
		// the rounding variant rounds the result to the upper word --
		// (result + 0x8000) with the low 16 bits cleared.
		val = LOGAND(ADD(val, UN(40, 0x8000)), UN(40, 0xffffff0000ULL));
	}
	RzILOpEffect *eff = SETG(dri->il_var, val);
	if (m1->kind == C55_OP_MEM) {
		RzILOpEffect *post = c55_post_effect(a, &m1p);
		if (post) {
			eff = SEQ2(eff, post);
		}
	}
	if (m2 != m1 && m2 != dst && m2->kind == C55_OP_MEM) {
		RzILOpEffect *post = c55_post_effect(a, &m2p);
		if (post) {
			eff = SEQ2(eff, post);
		}
	}
	if (side_load && m1->kind == C55_OP_MEM) {
		// memory-MAC side-load ([T3 = ]Smem): the Smem word is also written
		// into T3, sequenced before the multiply / accumulate effect.
		const C55RegInfo *t3 = a->reg_info ? a->reg_info(C55_RC_T, 3, C55_SUB_NONE) : NULL;
		RzILOpPure *ld = c55_read(a, &m1p);
		if (t3 && t3->il_var && ld) {
			eff = SEQ2(SETG(t3->il_var, ld), eff);
		} else {
			rz_il_op_pure_free(ld);
		}
	}
	return eff;
}

RzILOpEffect *c55_lift(const C55ArchDesc *a, const C55Insn *insn, ut64 pc) {
	if (!a || !insn) {
		return NULL;
	}
	if (insn->parallel_pair) {
		// "||" parallel pair: lift the two sub-instructions and sequence them. The
		// pair is treated as executing both halves; the architectural single-cycle
		// parallelism is not otherwise modelled. If either half does not lift, the
		// pair does not lift (matching the legacy lifter, which had no IL here).
		C55Insn s1, s2;
		if (!c55_decode(a, insn->par_bytes + insn->par_off1, insn->size - insn->par_off1, &s1) ||
			!c55_decode(a, insn->par_bytes + insn->par_off2, insn->size - insn->par_off2, &s2)) {
			return NULL;
		}
		// xccpart guards the *other* sub-instruction: it executes only when the
		// xccpart condition holds. (Plain xcc guards the following instruction,
		// not the parallel one, so it sequences normally below.)
		const C55Insn *guard = s1.xcc_guard ? &s1 : (s2.xcc_guard ? &s2 : NULL);
		if (guard) {
			const C55Insn *body = guard == &s1 ? &s2 : &s1;
			RzILOpEffect *be = c55_lift(a, body, pc);
			if (!be) {
				return NULL;
			}
			const C55Operand *cond = NULL;
			for (ut8 i = 0; i < guard->n_ops; i++) {
				if (guard->ops[i].kind == C55_OP_COND) {
					cond = &guard->ops[i];
					break;
				}
			}
			RzILOpPure *pred = cond ? c55_cond_pred(a, cond, guard->uns_all) : NULL;
			if (!pred) {
				rz_il_op_effect_free(be);
				return NULL;
			}
			return BRANCH(pred, be, NOP());
		}
		RzILOpEffect *e1 = c55_lift(a, &s1, pc);
		RzILOpEffect *e2 = c55_lift(a, &s2, pc);
		if (!e1 || !e2) {
			rz_il_op_effect_free(e1);
			rz_il_op_effect_free(e2);
			return NULL;
		}
		return SEQ2(e1, e2);
	}
	if (a->lift) {
		// arch-specific override takes precedence when it produces something
		RzILOpEffect *e = a->lift(insn, pc);
		if (e) {
			return e;
		}
	}
	if (insn->dual) {
		// dual "::" MAC: two parallel sub-MACs sharing the Cmem coefficient.
		// sub1 = ops[0..2] (Xmem, Cmem, ACx), sub2 = ops[3..5] (Ymem, Cmem, ACy);
		// an amar sub1 only post-modifies its Xmem pointer (no product). The shared
		// Cmem post-modify is emitted by each sub-MAC, matching the hardware's
		// twice-applied coefficient update. Dispatched here (not via the op type)
		// since the amar forms classify as LEA, not MUL.
		RzILOpEffect *e1, *e2;
		if (insn->amar1) {
			C55Operand xp = insn->ops[0];
			if (xp.kind == C55_OP_MEM && xp.reg.cls == C55_RC_AR) {
				xp.reg.cls = C55_RC_XAR;
			}
			e1 = c55_post_effect(a, &xp);
			if (!e1) {
				e1 = NOP();
			}
		} else {
			e1 = c55_mac_effect(a, &insn->ops[0], 3, insn->lop, insn->round, insn->shift1, false, false);
		}
		e2 = c55_mac_effect(a, &insn->ops[3], 3, insn->lop2, insn->round, insn->shift2, false, false);
		if (!e1 || !e2) {
			if (e1) {
				rz_il_op_effect_free(e1);
			}
			if (e2) {
				rz_il_op_effect_free(e2);
			}
			return NULL;
		}
		return SEQ2(e1, e2);
	}
	if (insn->lop == C55_LOP_FIRSADD || insn->lop == C55_LOP_FIRSSUB) {
		// FIRSADD / FIRSSUB Xmem, Ymem, Cmem, ACx, ACy: two parallel operations,
		//   ACy = ACy + (ACx(32-16) * Cmem)
		//   :: ACx = (Xmem << #16) +/- (Ymem << #16)
		// The MAC reads the old ACx high word (bits 31-16, sign-extended) times the
		// sign-extended Cmem; the ALU op forms the (anti)symmetric sum of the two
		// sign-extended data words, each shifted left 16. ops: [0]=Xmem [1]=Ymem
		// [2]=Cmem [3]=ACx [4]=ACy. Memory post-modify side effects follow.
		if (insn->n_ops != 5) {
			return NULL;
		}
		const C55Operand *acx = &insn->ops[3];
		const C55Operand *acy = &insn->ops[4];
		const C55RegInfo *xi = a->reg_info ? a->reg_info(acx->reg.cls, acx->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *yi = a->reg_info ? a->reg_info(acy->reg.cls, acy->reg.num, C55_SUB_NONE) : NULL;
		if (acx->kind != C55_OP_REG || acy->kind != C55_OP_REG ||
			!xi || !xi->il_var || xi->width != 40 || !yi || !yi->il_var || yi->width != 40) {
			return NULL;
		}
		C55Operand xp = insn->ops[0], yp = insn->ops[1], cp = insn->ops[2];
		if (xp.kind == C55_OP_MEM && xp.reg.cls == C55_RC_AR) {
			xp.reg.cls = C55_RC_XAR;
		}
		if (yp.kind == C55_OP_MEM && yp.reg.cls == C55_RC_AR) {
			yp.reg.cls = C55_RC_XAR;
		}
		if (cp.kind == C55_OP_MEM && cp.reg.cls == C55_RC_AR) {
			cp.reg.cls = C55_RC_XAR; // the Cmem pointer post-modify is 24-bit, like Xmem/Ymem
		}
		// MAC: ACy += ACx(31-16, sign-extended) * Cmem(sign-extended)
		C55Operand acx_hi = *acx;
		acx_hi.reg.sub = C55_SUB_HI;
		RzILOpPure *hi = c55_read(a, &acx_hi); // 16-bit high word
		RzILOpPure *cm = c55_mul_val(a, &cp); // Cmem -> 40-bit (signed)
		RzILOpPure *xs = c55_mul_val(a, &xp); // Xmem -> 40-bit (signed)
		RzILOpPure *ys = c55_mul_val(a, &yp); // Ymem -> 40-bit (signed)
		if (!hi || !cm || !xs || !ys) {
			rz_il_op_pure_free(hi);
			rz_il_op_pure_free(cm);
			rz_il_op_pure_free(xs);
			rz_il_op_pure_free(ys);
			return NULL;
		}
		RzILOpEffect *e1 = SETG(yi->il_var, ADD(VARG(yi->il_var), MUL(SIGNED(40, hi), cm)));
		RzILOpPure *sx = SHIFTL(IL_FALSE, xs, UN(8, 16));
		RzILOpPure *sy = SHIFTL(IL_FALSE, ys, UN(8, 16));
		RzILOpPure *sum = (insn->lop == C55_LOP_FIRSADD) ? ADD(sx, sy) : SUB(sx, sy);
		RzILOpEffect *eff = SEQ2(e1, SETG(xi->il_var, sum));
		RzILOpEffect *px = c55_post_effect(a, &xp);
		if (px) {
			eff = SEQ2(eff, px);
		}
		RzILOpEffect *py = c55_post_effect(a, &yp);
		if (py) {
			eff = SEQ2(eff, py);
		}
		RzILOpEffect *pc = c55_post_effect(a, &cp);
		if (pc) {
			eff = SEQ2(eff, pc);
		}
		return eff;
	}
	if (insn->lop == C55_LOP_SQDST || insn->lop == C55_LOP_ABDST) {
		// SQDST / ABDST Xmem, Ymem, ACx, ACy: two parallel operations,
		//   ACy = ACy + (ACx.h * ACx.h)   (sqdst)   or   ACy + |ACx.h|   (abdst)
		//   :: ACx = (Xmem << #16) - (Ymem << #16)
		// The MAC squares (sqdst) or takes the absolute value (abdst) of the
		// sign-extended ACx high word (bits 31-16); the ALU op forms the shifted
		// difference of the two sign-extended data words. ops: [0]=Xmem [1]=Ymem
		// [2]=ACx [3]=ACy. Memory post-modify side effects follow.
		if (insn->n_ops != 4) {
			return NULL;
		}
		const C55Operand *acx = &insn->ops[2];
		const C55Operand *acy = &insn->ops[3];
		const C55RegInfo *xi = a->reg_info ? a->reg_info(acx->reg.cls, acx->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *yi = a->reg_info ? a->reg_info(acy->reg.cls, acy->reg.num, C55_SUB_NONE) : NULL;
		if (acx->kind != C55_OP_REG || acy->kind != C55_OP_REG ||
			!xi || !xi->il_var || xi->width != 40 || !yi || !yi->il_var || yi->width != 40) {
			return NULL;
		}
		C55Operand xp = insn->ops[0], yp = insn->ops[1];
		if (xp.kind == C55_OP_MEM && xp.reg.cls == C55_RC_AR) {
			xp.reg.cls = C55_RC_XAR;
		}
		if (yp.kind == C55_OP_MEM && yp.reg.cls == C55_RC_AR) {
			yp.reg.cls = C55_RC_XAR;
		}
		C55Operand acx_hi = *acx;
		acx_hi.reg.sub = C55_SUB_HI;
		RzILOpPure *term;
		if (insn->lop == C55_LOP_SQDST) {
			// ACx.h * ACx.h, both sign-extended to 40 bits
			term = MUL(SIGNED(40, c55_read(a, &acx_hi)), SIGNED(40, c55_read(a, &acx_hi)));
		} else {
			// |ACx.h| : (s <= 0) ? -s : s (with -0 == 0 the <=0 boundary is exact)
			term = ITE(SLE(SIGNED(40, c55_read(a, &acx_hi)), UN(40, 0)),
				SUB(UN(40, 0), SIGNED(40, c55_read(a, &acx_hi))),
				SIGNED(40, c55_read(a, &acx_hi)));
		}
		RzILOpPure *xs = c55_mul_val(a, &xp); // Xmem -> 40-bit (signed)
		RzILOpPure *ys = c55_mul_val(a, &yp); // Ymem -> 40-bit (signed)
		if (!xs || !ys) {
			rz_il_op_pure_free(xs);
			rz_il_op_pure_free(ys);
			rz_il_op_pure_free(term);
			return NULL;
		}
		RzILOpEffect *e2 = SETG(xi->il_var, SUB(SHIFTL(IL_FALSE, xs, UN(8, 16)), SHIFTL(IL_FALSE, ys, UN(8, 16))));
		RzILOpEffect *eff = SEQ2(SETG(yi->il_var, ADD(VARG(yi->il_var), term)), e2);
		RzILOpEffect *px = c55_post_effect(a, &xp);
		if (px) {
			eff = SEQ2(eff, px);
		}
		RzILOpEffect *py = c55_post_effect(a, &yp);
		if (py) {
			eff = SEQ2(eff, py);
		}
		return eff;
	}
	if (insn->lop == C55_LOP_LMS) {
		// LMS Xmem, Ymem, ACx, ACy: two parallel operations,
		//   ACy = ACy + (Xmem * Ymem)
		//   :: ACx = round(ACx + (Xmem << #16))
		// The first is a MAC of the two sign-extended data words; the second adds
		// Xmem (shifted left 16) to ACx and rounds to the upper word. Both read the
		// old ACx, so it is snapshotted into a local first (the two destinations may
		// alias). ops: [0]=Xmem [1]=Ymem [2]=ACx [3]=ACy; post-modifies follow.
		if (insn->n_ops != 4) {
			return NULL;
		}
		const C55Operand *acx = &insn->ops[2];
		const C55Operand *acy = &insn->ops[3];
		const C55RegInfo *xi = a->reg_info ? a->reg_info(acx->reg.cls, acx->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *yi = a->reg_info ? a->reg_info(acy->reg.cls, acy->reg.num, C55_SUB_NONE) : NULL;
		if (acx->kind != C55_OP_REG || acy->kind != C55_OP_REG ||
			!xi || !xi->il_var || xi->width != 40 || !yi || !yi->il_var || yi->width != 40) {
			return NULL;
		}
		C55Operand xp = insn->ops[0], yp = insn->ops[1];
		if (xp.kind == C55_OP_MEM && xp.reg.cls == C55_RC_AR) {
			xp.reg.cls = C55_RC_XAR;
		}
		if (yp.kind == C55_OP_MEM && yp.reg.cls == C55_RC_AR) {
			yp.reg.cls = C55_RC_XAR;
		}
		RzILOpPure *xm = c55_mul_val(a, &xp); // Xmem for the multiply
		RzILOpPure *ym = c55_mul_val(a, &yp); // Ymem
		RzILOpPure *xs = c55_mul_val(a, &xp); // Xmem for the shifted add
		if (!xm || !ym || !xs) {
			rz_il_op_pure_free(xm);
			rz_il_op_pure_free(ym);
			rz_il_op_pure_free(xs);
			return NULL;
		}
		// ACx = round(old_ACx + (Xmem << #16)); round to the upper word.
		RzILOpPure *sum = ADD(VARL("lms_acx"), SHIFTL(IL_FALSE, xs, UN(8, 16)));
		sum = LOGAND(ADD(sum, UN(40, 0x8000)), UN(40, 0xffffff0000ULL));
		RzILOpEffect *eff = SEQ2(SETL("lms_acx", VARG(xi->il_var)),
			SETG(yi->il_var, ADD(VARG(yi->il_var), MUL(xm, ym))));
		eff = SEQ2(eff, SETG(xi->il_var, sum));
		RzILOpEffect *px = c55_post_effect(a, &xp);
		if (px) {
			eff = SEQ2(eff, px);
		}
		RzILOpEffect *py = c55_post_effect(a, &yp);
		if (py) {
			eff = SEQ2(eff, py);
		}
		return eff;
	}
	if (insn->mac_mov) {
		// MAC :: parallel load: sub1 = macm/masm Xmem, Tx, ACx (a Tx-coefficient
		// memory MAC; side_load -> T3=Xmem); sub2 = mov Ymem << #16, ACy. The mov does
		// not read ACy, so no aliasing snapshot is needed (when ACx==ACy the load
		// simply wins). ops: [0]=Xmem [1]=Tx [2]=ACx [3]=Ymem [4]=ACy.
		if (insn->n_ops != 5) {
			return NULL;
		}
		const C55Operand *acy = &insn->ops[4];
		const C55RegInfo *yi = a->reg_info ? a->reg_info(acy->reg.cls, acy->reg.num, C55_SUB_NONE) : NULL;
		if (acy->kind != C55_OP_REG || !yi || !yi->il_var || yi->width != 40) {
			return NULL;
		}
		C55Operand yp = insn->ops[3];
		if (yp.kind == C55_OP_MEM && yp.reg.cls == C55_RC_AR) {
			yp.reg.cls = C55_RC_XAR;
		}
		RzILOpPure *yv = c55_mul_val(a, &yp); // Ymem -> 40-bit (signed)
		if (!yv) {
			return NULL;
		}
		RzILOpEffect *sub1 = c55_mac_effect(a, &insn->ops[0], 3, insn->lop, insn->round, false, false, insn->side_load);
		if (!sub1) {
			rz_il_op_pure_free(yv);
			return NULL;
		}
		RzILOpEffect *eff = SEQ2(sub1, SETG(yi->il_var, SHIFTL(IL_FALSE, yv, UN(8, 16))));
		RzILOpEffect *py = c55_post_effect(a, &yp);
		if (py) {
			eff = SEQ2(eff, py);
		}
		return eff;
	}
	// Register or immediate shift (sftl / sfts ACx, Tx|#SHIFTW [, ACy]): a
	// three-operand form the two-operand lop branch below cannot express. A
	// negative count shifts right by its magnitude, a positive count shifts
	// left; sftl fills logically (zero), sfts fills the right shift with the
	// sign bit. ACy collapses onto ACx when they are equal.
	if (insn->lop == C55_LOP_SFTL || insn->lop == C55_LOP_SFTS) {
		if (insn->n_ops < 2) {
			return NULL;
		}
		const C55Operand *acx = &insn->ops[0];
		const C55Operand *cnt = &insn->ops[1];
		const C55Operand *acy = &insn->ops[insn->n_ops >= 3 ? 2 : 0];
		if (acx->kind != C55_OP_REG || acy->kind != C55_OP_REG) {
			return NULL;
		}
		// A half-register source or destination (the 0xa6/0xa7 .h/.l shift
		// forms) operates on a 16-bit slice and merges the result back into the
		// destination half. Both operands must be halves; a mixed full/half
		// shape is left unlifted.
		bool acx_half = acx->reg.sub == C55_SUB_HI || acx->reg.sub == C55_SUB_LO;
		bool acy_half = acy->reg.sub == C55_SUB_HI || acy->reg.sub == C55_SUB_LO;
		if (acx_half || acy_half) {
			if (!acx_half || !acy_half) {
				return NULL;
			}
			bool harith = insn->lop == C55_LOP_SFTS;
			if (cnt->kind == C55_OP_REG) {
				// count register (a T register or an accumulator sub-word read
				// as its 16-bit value): its sign selects the direction.
				RzILOpPure *fill = harith ? MSB(c55_read(a, acx)) : IL_FALSE;
				RzILOpPure *res = ITE(
					AND(SLE(c55_read(a, cnt), UN(16, 0)), INV(IS_ZERO(c55_read(a, cnt)))),
					SHIFTR(fill, c55_read(a, acx), SUB(UN(16, 0), c55_read(a, cnt))),
					SHIFTL(IL_FALSE, c55_read(a, acx), c55_read(a, cnt)));
				return c55_write(a, acy, res);
			}
			// Only an immediate (decode-time) count is modelled otherwise.
			if (cnt->kind == C55_OP_IMM) {
				ut32 w = cnt->width ? cnt->width : 6;
				st64 s = (st64)(cnt->imm << (64 - w)) >> (64 - w);
				if (s == 0) {
					return c55_write(a, acy, c55_read(a, acx));
				}
				if (s > 0) {
					return c55_write(a, acy, SHIFTL(IL_FALSE, c55_read(a, acx), UN(w, (ut64)s)));
				}
				RzILOpPure *fill = harith ? MSB(c55_read(a, acx)) : IL_FALSE;
				return c55_write(a, acy, SHIFTR(fill, c55_read(a, acx), UN(w, (ut64)(-s))));
			}
			return NULL;
		}
		const C55RegInfo *xi = a->reg_info ? a->reg_info(acx->reg.cls, acx->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *yi = a->reg_info ? a->reg_info(acy->reg.cls, acy->reg.num, C55_SUB_NONE) : NULL;
		if (!xi || !yi || !xi->il_var || !yi->il_var) {
			return NULL;
		}
		bool arith = insn->lop == C55_LOP_SFTS;
		if (cnt->kind == C55_OP_REG) {
			// count in a T register: the direction depends on its sign at runtime.
			const C55RegInfo *ti = a->reg_info ? a->reg_info(cnt->reg.cls, cnt->reg.num, C55_SUB_NONE) : NULL;
			if (!ti || !ti->il_var) {
				return NULL;
			}
			RzILOpPure *fill = arith ? MSB(VARG(xi->il_var)) : IL_FALSE;
			return SETG(yi->il_var,
				ITE(AND(SLE(VARG(ti->il_var), UN(ti->width, 0)), INV(EQ(VARG(ti->il_var), UN(ti->width, 0)))),
					SHIFTR(fill, VARG(xi->il_var), SUB(UN(ti->width, 0), VARG(ti->il_var))),
					SHIFTL(IL_FALSE, VARG(xi->il_var), VARG(ti->il_var))));
		}
		if (cnt->kind == C55_OP_IMM) {
			// #SHIFTW is a decode-time signed count: sign-extend the field, then
			// emit a fixed left or right shift of that magnitude. A zero count is
			// a plain move (no shift node), matching the legacy lifter.
			ut32 w = cnt->width ? cnt->width : 6;
			st64 s = (st64)(cnt->imm << (64 - w)) >> (64 - w);
			if (s == 0) {
				return SETG(yi->il_var, VARG(xi->il_var));
			}
			if (s > 0) {
				return SETG(yi->il_var, SHIFTL(IL_FALSE, VARG(xi->il_var), UN(w, (ut64)s)));
			}
			RzILOpPure *fill = arith ? MSB(VARG(xi->il_var)) : IL_FALSE;
			return SETG(yi->il_var, SHIFTR(fill, VARG(xi->il_var), UN(w, (ut64)(-s))));
		}
		return NULL;
	}
	// Immediate-ALU with immediate shift: ACy = ACx <op> (#k16 << #sh) for the
	// opcode-0x7a (fixed sh=16) and opcode-0x70..0x74 (variable sh) add/sub/and/
	// or/xor forms. Distinguished from the register-shift forms below by a
	// leading immediate operand (ops = [#k16, ACx, ACy]). The shift count is the
	// operand's shamt.
	// Immediate shifted-load: dst = sign-extend(#k16) << #sh for the opcode-0xc2
	// "mov #k16 << #sh, ACx" form (ops = [#k16, ACx]). The shift count is the
	// immediate operand's shamt.
	if (insn->lop == C55_LOP_MOVSHL && insn->n_ops >= 2 && insn->ops[0].kind == C55_OP_IMM) {
		const C55Operand *imm = &insn->ops[0];
		const C55Operand *dst = &insn->ops[1];
		if (dst->kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *yi = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!yi || !yi->il_var) {
			return NULL;
		}
		ut64 k16sign = imm->imm & 0xffff;
		if (k16sign & 0x8000) {
			k16sign |= 0xffffff0000ULL;
		}
		// The shift amount is an assemble-time constant, so the legacy decoder
		// folds "#k16 << #sh" to a single constant; reproduce that (the result
		// is masked to the destination width).
		ut64 folded = (k16sign << (imm->shamt & 0x3f));
		if (yi->width < 64) {
			folded &= ((ut64)1 << yi->width) - 1;
		}
		return SETG(yi->il_var, UN(yi->width, folded));
	}
	if ((insn->lop == C55_LOP_ANDSHL || insn->lop == C55_LOP_ORSHL || insn->lop == C55_LOP_XORSHL ||
		    insn->lop == C55_LOP_ADDSHL || insn->lop == C55_LOP_SUBSHL) &&
		insn->n_ops >= 3 && insn->ops[0].kind == C55_OP_IMM) {
		const C55Operand *imm = &insn->ops[0];
		const C55Operand *src = &insn->ops[1];
		const C55Operand *dst = &insn->ops[2];
		if (src->kind != C55_OP_REG || dst->kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *xi = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *yi = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!xi || !yi || !xi->il_var || !yi->il_var) {
			return NULL;
		}
		// add/sub treat #k16 as a signed constant (sign-extended to the
		// accumulator width); the bitwise and/or/xor forms treat it as a raw
		// bit pattern (zero-extended). Both then shift up 16 bits.
		ut64 k16sign = imm->imm & 0xffff;
		if ((insn->lop == C55_LOP_ADDSHL || insn->lop == C55_LOP_SUBSHL) && (k16sign & 0x8000)) {
			k16sign |= 0xffffff0000ULL;
		}
		RzILOpPure *shifted = SHIFTL(IL_FALSE, UN(yi->width, k16sign), UN(8, (ut64)(ut8)imm->shamt));
		RzILOpPure *res;
		switch (insn->lop) {
		case C55_LOP_ADDSHL: res = ADD(VARG(xi->il_var), shifted); break;
		case C55_LOP_SUBSHL: res = SUB(VARG(xi->il_var), shifted); break;
		case C55_LOP_ANDSHL: res = LOGAND(VARG(xi->il_var), shifted); break;
		case C55_LOP_ORSHL: res = LOGOR(VARG(xi->il_var), shifted); break;
		default: res = LOGXOR(VARG(xi->il_var), shifted); break;
		}
		return SETG(yi->il_var, res);
	}
	// Immediate ALU without shift: dst = ACx <op> zero-extend(#k16) for the
	// 0x7b-0x7f forms (ops = [#k16, gr4-src, gr4-dst]). The legacy lifts only
	// the accumulator-source encodings -- a 16-bit T / AR source is left
	// unlifted -- which is reproduced here; the 40-bit result is truncated to a
	// 16-bit destination.
	if (insn->lop == C55_LOP_ADDK || insn->lop == C55_LOP_SUBK ||
		insn->lop == C55_LOP_ANDK || insn->lop == C55_LOP_ORK || insn->lop == C55_LOP_XORK) {
		if (insn->n_ops < 3 || insn->ops[0].kind != C55_OP_IMM) {
			return NULL;
		}
		const C55Operand *imm = &insn->ops[0];
		const C55Operand *src = &insn->ops[1];
		const C55Operand *dst = &insn->ops[2];
		if (src->kind != C55_OP_REG || dst->kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *xi = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *yi = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!xi || !yi || !xi->il_var || !yi->il_var) {
			return NULL;
		}
		bool bitwise = insn->lop == C55_LOP_ANDK || insn->lop == C55_LOP_ORK || insn->lop == C55_LOP_XORK;
		// Accumulator-half operands (only the 0xc4/0xc5 gr1 forms carry these):
		// the operation runs at the destination width, reading the source through
		// c55_read (a half yields its 16-bit value) and writing back through
		// c55_write (a half does the read-modify-write merge). The legacy lifts
		// only the bitwise ops here, and only when the source is at least as wide
		// as the destination (a narrower source -> destination promotion is left
		// unlifted); add/sub with a half operand are not lifted.
		bool src_half = src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO;
		bool dst_half = dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO;
		if (src_half || dst_half) {
			if (!bitwise) {
				// add/sub on accumulator halves: operate on the 16-bit slice.
				// A .L destination updates [15:0]; a .H destination updates
				// [39:16] (sign-extended through the guard) per SWPU104 1.5.1.
				if (!dst_half) {
					return NULL;
				}
				RzILOpPure *sv = c55_read(a, src);
				if (!src_half && xi->width > 16) {
					sv = CAST(16, IL_FALSE, sv); // truncate a full source to 16 bits
				}
				RzILOpPure *res16 = (insn->lop == C55_LOP_ADDK)
					? ADD(sv, UN(16, (ut64)(imm->imm & 0xffff)))
					: SUB(sv, UN(16, (ut64)(imm->imm & 0xffff)));
				return c55_write_half_arith(a, dst, res16);
			}
			ut8 dw = dst_half ? 16 : yi->width;
			ut8 sw = src_half ? 16 : xi->width;
			if (sw < dw) {
				// bitwise with a 16-bit source (a half, or an AR/T register)
				// into a full accumulator: the source and the immediate are
				// zero-extended to 40 bits and a 40-bit bitwise op is performed
				// (SWPU104 6.6.1), i.e. the result is the zero-extended 16-bit
				// op.
				RzILOpPure *sv = c55_read(a, src);
				if (!src_half && xi->width > 16) {
					sv = CAST(16, IL_FALSE, sv);
				}
				RzILOpPure *iv = UN(16, (ut64)(imm->imm & 0xffff));
				RzILOpPure *r16 = insn->lop == C55_LOP_ANDK ? LOGAND(sv, iv)
					: insn->lop == C55_LOP_ORK          ? LOGOR(sv, iv)
									    : LOGXOR(sv, iv);
				return SETG(yi->il_var, UNSIGNED(yi->width, r16));
			}
			RzILOpPure *sv = c55_read(a, src); // 16-bit for a half, else full
			if (sw > dw) {
				sv = CAST(dw, IL_FALSE, sv); // truncate a full source to the half width
			}
			RzILOpPure *iv = UN(dw, (ut64)(imm->imm & 0xffff));
			RzILOpPure *r = insn->lop == C55_LOP_ANDK ? LOGAND(sv, iv)
				: insn->lop == C55_LOP_ORK        ? LOGOR(sv, iv)
								  : LOGXOR(sv, iv);
			return c55_write(a, dst, r);
		}
		RzILOpPure *res;
		if (bitwise && yi->width < xi->width) {
			// and / or / xor into a 16-bit (T / AR) destination: the legacy
			// truncates the accumulator first and operates at the destination
			// width with a same-width immediate (no outer cast).
			RzILOpPure *sv = CAST(yi->width, IL_FALSE, VARG(xi->il_var));
			RzILOpPure *iv = UN(yi->width, (ut64)(imm->imm & 0xffff));
			res = insn->lop == C55_LOP_ANDK ? LOGAND(sv, iv) : insn->lop == C55_LOP_ORK ? LOGOR(sv, iv)
												    : LOGXOR(sv, iv);
		} else {
			// add / sub operate at the 40-bit accumulator width. The elided
			// 2-operand form (destination == source) zero-extends #k16; the
			// 3-operand form sign-extends it. The bitwise ops always zero-extend
			// and truncate to a 16-bit destination above; here they zero-extend.
			ut64 immv = (ut64)(imm->imm & 0xffff);
			bool same = src->reg.cls == dst->reg.cls && src->reg.num == dst->reg.num;
			if ((insn->lop == C55_LOP_ADDK || insn->lop == C55_LOP_SUBK) && !same && (immv & 0x8000)) {
				immv |= 0xffffff0000ULL;
			}
			RzILOpPure *iv = UN(xi->width, immv);
			switch (insn->lop) {
			case C55_LOP_ADDK: res = ADD(VARG(xi->il_var), iv); break;
			case C55_LOP_SUBK: res = SUB(VARG(xi->il_var), iv); break;
			case C55_LOP_ANDK: res = LOGAND(VARG(xi->il_var), iv); break;
			case C55_LOP_ORK: res = LOGOR(VARG(xi->il_var), iv); break;
			default: res = LOGXOR(VARG(xi->il_var), iv); break;
			}
			if (yi->width < xi->width) {
				res = CAST(yi->width, IL_FALSE, res);
			}
		}
		return SETG(yi->il_var, res);
	}
	// Shift-and-combine: dst = dst <op> (src << #SHIFTW) for the 0x10 and / or /
	// xor / add / sub register-ALU forms. The legacy renders and lifts the shift
	// as an unsigned 8-bit left shift of the raw SHIFTW field (it does not treat
	// the field as signed here); this preserves that behaviour byte-for-byte. The
	// and / or / xor forms collapse the destination when it equals the source and
	// the legacy leaves the collapsed encodings unlifted, so those return null and
	// fall through to the (also null) legacy IL.
	if (insn->lop == C55_LOP_ANDSHL || insn->lop == C55_LOP_ORSHL || insn->lop == C55_LOP_XORSHL ||
		insn->lop == C55_LOP_ADDSHL || insn->lop == C55_LOP_SUBSHL) {
		if (insn->n_ops < 2) {
			return NULL;
		}
		bool bitwise = insn->lop == C55_LOP_ANDSHL || insn->lop == C55_LOP_ORSHL || insn->lop == C55_LOP_XORSHL;
		if (bitwise && insn->n_ops < 3) {
			return NULL; // collapsed and/or/xor: left to the legacy (unlifted)
		}
		const C55Operand *src = &insn->ops[0];
		const C55Operand *cnt = &insn->ops[1];
		const C55Operand *dst = &insn->ops[insn->n_ops >= 3 ? 2 : 0];
		if (src->kind != C55_OP_REG || dst->kind != C55_OP_REG ||
			(cnt->kind != C55_OP_IMM && cnt->kind != C55_OP_REG)) {
			return NULL;
		}
		// Half-register shift-ALU (the 0xa7 .h/.l forms): operate on the 16-bit
		// slice. ACy.<sub> = ACy.<sub> <op> (ACx.<sub> shifted by the signed S6
		// count, logically). Only the immediate-count form is modelled; a .L
		// destination merges [15:0], and for add/sub a .H destination
		// sign-extends through the guard.
		bool sh_src_half = src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO;
		bool sh_dst_half = dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO;
		if (sh_src_half || sh_dst_half) {
			if (!sh_src_half || !sh_dst_half || cnt->kind != C55_OP_IMM) {
				return NULL; // mixed half/full or register-count: unlifted
			}
			st32 s6 = (st32)(((ut32)(cnt->imm & 0x3f)) << 26) >> 26; // sign-extend 6-bit
			RzILOpPure *sv = c55_read(a, src);
			RzILOpPure *shifted = (s6 >= 0)
				? SHIFTL(IL_FALSE, sv, UN(8, (ut64)s6))
				: SHIFTR(IL_FALSE, sv, UN(8, (ut64)(-s6)));
			RzILOpPure *dv = c55_read(a, dst);
			RzILOpPure *res16;
			switch (insn->lop) {
			case C55_LOP_ADDSHL: res16 = ADD(dv, shifted); break;
			case C55_LOP_SUBSHL: res16 = SUB(dv, shifted); break;
			case C55_LOP_ANDSHL: res16 = LOGAND(dv, shifted); break;
			case C55_LOP_ORSHL: res16 = LOGOR(dv, shifted); break;
			default: res16 = LOGXOR(dv, shifted); break;
			}
			bool arith = insn->lop == C55_LOP_ADDSHL || insn->lop == C55_LOP_SUBSHL;
			return arith ? c55_write_half_arith(a, dst, res16) : c55_write(a, dst, res16);
		}
		const C55RegInfo *xi = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *yi = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!xi || !yi || !xi->il_var || !yi->il_var) {
			return NULL;
		}
		RzILOpPure *shifted;
		if (cnt->kind == C55_OP_IMM) {
			// "src << #SHIFTW": the legacy treats the field as an unsigned 8-bit
			// left-shift amount (0x10 and/or/xor/add/sub register-ALU forms).
			shifted = SHIFTL(IL_FALSE, VARG(xi->il_var), UN(8, (ut64)(cnt->imm & 0xff)));
		} else {
			// "src << Tx": the shift count is a (16-bit) T register (opcode 0x5a
			// add/sub ACx << Tx, ACy).
			const C55RegInfo *ti = a->reg_info ? a->reg_info(cnt->reg.cls, cnt->reg.num, C55_SUB_NONE) : NULL;
			if (!ti || !ti->il_var) {
				return NULL;
			}
			shifted = SHIFTL(IL_FALSE, VARG(xi->il_var), VARG(ti->il_var));
		}
		RzILOpPure *res = NULL;
		switch (insn->lop) {
		case C55_LOP_ANDSHL: res = LOGAND(VARG(yi->il_var), shifted); break;
		case C55_LOP_ORSHL: res = LOGOR(VARG(yi->il_var), shifted); break;
		case C55_LOP_XORSHL: res = LOGXOR(VARG(yi->il_var), shifted); break;
		case C55_LOP_ADDSHL: res = ADD(VARG(yi->il_var), shifted); break;
		case C55_LOP_SUBSHL: res = SUB(VARG(yi->il_var), shifted); break;
		default: rz_il_op_pure_free(shifted); return NULL;
		}
		return SETG(yi->il_var, res);
	}
	// bclr / bset st0_<bit>, st0_55: clear or set a named bit in st0_55.
	if (insn->lop == C55_LOP_STBITCLR || insn->lop == C55_LOP_STBITSET) {
		// ops[0] is the bit-name register (its index encodes the bit position,
		// 192 + bit), ops[1] is st0_55. Only the semantic bits (9..15: acov,
		// carry, tc) are lifted; the data-page bits (0..8) produce no IL, as in
		// the legacy lifter. The legacy form is an ite over a constant predicate:
		//   st0_55 = ite(set?, st0_55 | (1<<bit), st0_55 & ~(1<<bit)).
		if (insn->n_ops < 2 || insn->ops[0].kind != C55_OP_REG ||
			insn->ops[1].kind != C55_OP_REG) {
			return NULL;
		}
		if (insn->ops[0].reg.cls != C55_RC_SPECIAL || insn->ops[0].reg.num < 192 ||
			insn->ops[0].reg.num > 207) {
			return NULL;
		}
		unsigned bit = (unsigned)(insn->ops[0].reg.num - 192);
		if (bit < 9) {
			return NULL; // data-page bits: no IL, matching the legacy lifter
		}
		const C55RegInfo *ri = a->reg_info ? a->reg_info(insn->ops[1].reg.cls, insn->ops[1].reg.num, C55_SUB_NONE) : NULL;
		if (!ri || !ri->il_var) {
			return NULL;
		}
		ut64 one = 1ULL << bit;
		ut64 widthmask = (1ULL << ri->width) - 1;
		RzILOpEffect *r = SETG(ri->il_var,
			ITE(insn->lop == C55_LOP_STBITSET ? IL_TRUE : IL_FALSE,
				LOGOR(VARG(ri->il_var), UN(ri->width, one & widthmask)),
				LOGAND(VARG(ri->il_var), UN(ri->width, (~one) & widthmask))));
		return r;
	}
	// Status-register bit clear / set (opcode 0x46): STx = STx & ~(1 << #k4)
	// (bclr) or STx | (1 << #k4) (bset), with ops[0] the #k4 bit index and
	// ops[1] the status register. The same handler covers the register bit
	// ops bclr/bset/bnot @#k, ACx[.h/.l]/ARx (opcode 0x89), whose bit number is
	// a full is_bit() immediate taken relative to the addressed sub-register
	// (so a .h operand targets bit k+16, the guard bit k+32 of the accumulator)
	// and whose bnot form toggles the bit.
	if (insn->lop == C55_LOP_BITCLR || insn->lop == C55_LOP_BITSET || insn->lop == C55_LOP_BITNOT) {
		if (insn->n_ops < 2) {
			return NULL;
		}
		const C55Operand *bit = &insn->ops[0];
		const C55Operand *reg = &insn->ops[1];
		if (bit->kind != C55_OP_IMM || reg->kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *ri = a->reg_info ? a->reg_info(reg->reg.cls, reg->reg.num, C55_SUB_NONE) : NULL;
		if (!ri || !ri->il_var) {
			return NULL;
		}
		unsigned b;
		if (bit->is_bit) {
			unsigned off = (reg->reg.sub == C55_SUB_HI) ? 16 : (reg->reg.sub == C55_SUB_GUARD) ? 32
													   : 0;
			b = (unsigned)bit->imm + off;
		} else {
			b = (unsigned)(bit->imm & 0xf); // status-register #k4
		}
		if (b >= ri->width) {
			return NULL;
		}
		ut64 one = 1ULL << b;
		ut64 widthmask = (ri->width >= 64) ? ~0ULL : ((1ULL << ri->width) - 1);
		RzILOpPure *res = (insn->lop == C55_LOP_BITCLR) ? LOGAND(VARG(ri->il_var), UN(ri->width, (~one) & widthmask))
			: (insn->lop == C55_LOP_BITSET)         ? LOGOR(VARG(ri->il_var), UN(ri->width, one & widthmask))
								: LOGXOR(VARG(ri->il_var), UN(ri->width, one & widthmask));
		return SETG(ri->il_var, res);
	}
	// amov #k16, dst: load a zero-extended 16-bit constant (or address) into the
	// destination register (opcode 0x77). ops[0] is the constant, ops[1] the dst.
	if (insn->lop == C55_LOP_AMOV) {
		if (insn->n_ops < 2) {
			return NULL;
		}
		const C55Operand *imm = &insn->ops[0];
		const C55Operand *dst = &insn->ops[1];
		if (imm->kind != C55_OP_IMM || dst->kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *ri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!ri || !ri->il_var) {
			return NULL;
		}
		// amov #k, reg: load the unsigned constant into the pointer register.
		// When the constant does not fit the register width (a 24-bit field into
		// a 23-bit XARn), the legacy decoder leaves it unlifted; preserve that
		// correct-or-NULL behaviour rather than silently truncating an address.
		if (ri->width < 64 && ((ut64)imm->imm >> ri->width)) {
			return NULL;
		}
		return SETG(ri->il_var, UN(ri->width, (ut64)imm->imm));
	}
	// Instructions with no modelled data effect (repeat / loop control such as
	// rptb, rptcc) lift to a nop, matching the legacy lifter.
	if (insn->lop == C55_LOP_NOP) {
		return NOP();
	}
	// Decode-and-analyse-only instructions (the exponent / bit-count style DSP
	// primitives) carry no modelled data effect: no IL.
	if (insn->lop == C55_LOP_OPAQUE) {
		return NULL;
	}
	// amov / asub ACx, ACy register forms (opcode 0x14): ACy = ACx (amov) or
	// ACy = ACy - ACx (asub), with the source converted to the destination width
	// (zero-extended when narrower, truncated when wider; no cast when equal).
	// ops[0] is the source register, ops[1] the destination.
	if (insn->lop == C55_LOP_AREG_MOV || insn->lop == C55_LOP_AREG_SUB || insn->lop == C55_LOP_AREG_ADD ||
		insn->lop == C55_LOP_AREG_AND || insn->lop == C55_LOP_AREG_OR || insn->lop == C55_LOP_AREG_XOR) {
		if (insn->n_ops < 2 || !a->reg_info) {
			return NULL;
		}
		const C55Operand *src = &insn->ops[0];
		const C55Operand *dst = &insn->ops[1];
		if (dst->kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *di = a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE);
		if (!di || !di->il_var) {
			return NULL;
		}
		RzILOpPure *sv;
		if (src->kind == C55_OP_IMM) {
			// a{add,sub} #k, reg: add/subtract an unsigned constant to/from the
			// pointer. A constant that does not fit the register width is left
			// unlifted, matching the legacy decoder and the amov treatment.
			if (di->width < 64 && ((ut64)src->imm >> di->width)) {
				return NULL;
			}
			sv = UN(di->width, (ut64)src->imm);
		} else if (src->kind == C55_OP_REG) {
			const C55RegInfo *si = a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE);
			if (!si || !si->il_var) {
				return NULL;
			}
			sv = VARG(si->il_var);
			if (si->width != di->width) {
				sv = UNSIGNED(di->width, sv);
			}
		} else {
			return NULL;
		}
		if (insn->lop == C55_LOP_AREG_MOV) {
			return SETG(di->il_var, sv);
		}
		if (insn->lop == C55_LOP_AREG_ADD) {
			return SETG(di->il_var, ADD(VARG(di->il_var), sv));
		}
		if (insn->lop == C55_LOP_AREG_AND) {
			return SETG(di->il_var, LOGAND(VARG(di->il_var), sv));
		}
		if (insn->lop == C55_LOP_AREG_OR) {
			return SETG(di->il_var, LOGOR(VARG(di->il_var), sv));
		}
		if (insn->lop == C55_LOP_AREG_XOR) {
			return SETG(di->il_var, LOGXOR(VARG(di->il_var), sv));
		}
		return SETG(di->il_var, SUB(VARG(di->il_var), sv));
	}
	if (insn->lop == C55_LOP_RPTADD || insn->lop == C55_LOP_RPTSUB) {
		// rptadd/rptsub CSR, src: CSR = CSR +/- src. Unlike the A-unit
		// arithmetic above, the destination (CSR) is the FIRST operand and the
		// addend the second. The repeat behaviour these instructions also set
		// up (the following instruction executing CSR+1 times) is a hardware
		// loop that cannot be expressed one instruction at a time, but the
		// named CSR register write is a real architectural effect and is lifted.
		if (insn->n_ops < 2 || !a->reg_info) {
			return NULL;
		}
		const C55Operand *dst = &insn->ops[0];
		const C55Operand *src = &insn->ops[1];
		if (dst->kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *di = a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE);
		if (!di || !di->il_var) {
			return NULL;
		}
		RzILOpPure *sv;
		if (src->kind == C55_OP_IMM) {
			if (di->width < 64 && ((ut64)src->imm >> di->width)) {
				return NULL;
			}
			sv = UN(di->width, (ut64)src->imm);
		} else if (src->kind == C55_OP_REG) {
			const C55RegInfo *si = a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE);
			if (!si || !si->il_var) {
				return NULL;
			}
			sv = VARG(si->il_var);
			if (si->width != di->width) {
				sv = UNSIGNED(di->width, sv);
			}
		} else {
			return NULL;
		}
		return SETG(di->il_var,
			insn->lop == C55_LOP_RPTADD ? ADD(VARG(di->il_var), sv) : SUB(VARG(di->il_var), sv));
	}
	// cmp / cmpand / cmpor SRC <relop> DST, [TCx,] TCz (opcode 0x12): compare two
	// registers and write the TCz status bit. cmpand/cmpor first AND/OR the
	// comparison with the input TCx bit. ops[0] is the compare COND; for cmp
	// ops[1] is TCz, for cmpand/cmpor ops[1] is TCx and ops[2] is TCz. The 'u'
	// (unsigned) variants compare unsigned and zero-extend the 16-bit operands.
	if (insn->lop == C55_LOP_CMP || insn->lop == C55_LOP_CMPAND || insn->lop == C55_LOP_CMPOR) {
		bool andor = insn->lop != C55_LOP_CMP;
		if (insn->n_ops < (andor ? 3 : 2) || !a->reg_info) {
			return NULL;
		}
		const C55Operand *cond = &insn->ops[0];
		const C55Operand *tcx = andor ? &insn->ops[1] : NULL;
		const C55Operand *tcz = andor ? &insn->ops[2] : &insn->ops[1];
		if (cond->kind != C55_OP_COND || !cond->cmp_to_reg ||
			tcz->kind != C55_OP_COND || !tcz->cond_is_flag) {
			return NULL;
		}
		const C55RegInfo *si = a->reg_info(cond->reg.cls, cond->reg.num, C55_SUB_NONE);
		const C55RegInfo *di = a->reg_info(cond->index.cls, cond->index.num, C55_SUB_NONE);
		if (!si || !si->il_var || !di || !di->il_var) {
			return NULL;
		}
		RzILOpPure *pred = c55_cmp_pred(a, cond, insn->uns_all);
		if (!pred) {
			return NULL;
		}
		if (andor) {
			if (tcx->kind != C55_OP_COND || !tcx->cond_is_flag) {
				rz_il_op_pure_free(pred);
				return NULL;
			}
			// cond_flag 4/20 -> tc1 (bit 0x2000), 5/21 -> tc2 (bit 0x1000); ids
			// >= 20 are the negated !tcN inputs, which add an extra INV.
			ut64 xbit = (tcx->cond_flag & 1) ? 0x1000 : 0x2000;
			RzILOpPure *tcin = INV(IS_ZERO(LOGAND(VARG("st0_55"), UN(16, xbit))));
			if (tcx->cond_flag >= 20) {
				tcin = INV(tcin);
			}
			pred = (insn->lop == C55_LOP_CMPAND) ? AND(pred, tcin) : OR(pred, tcin);
		}
		ut64 zbit = (tcz->cond_flag & 1) ? 0x1000 : 0x2000;
		return SETG("st0_55", ITE(pred, LOGOR(VARG("st0_55"), UN(16, zbit)), LOGAND(VARG("st0_55"), UN(16, (~zbit) & 0xffff))));
	}
	// rol / ror BitIn, ACx, BitOut, ACy: rotate ACx left/right by one through a
	// status bit. The bit shifted in comes from st0_55 (carry = bit 11, tc2 =
	// bit 12), zero-extended to the 40-bit accumulator; the bit shifted out
	// (msb for rol, lsb for ror) is written to the rotate-out status bit. The
	// legacy models this only for accumulator src+dst, so other classes fall
	// through to a null lift.
	if (insn->lop == C55_LOP_ROL || insn->lop == C55_LOP_ROR) {
		if (insn->n_ops < 4 || !a->reg_info) {
			return NULL;
		}
		const C55Operand *bin = &insn->ops[0];
		const C55Operand *src = &insn->ops[1];
		const C55Operand *bout = &insn->ops[2];
		const C55Operand *dst = &insn->ops[3];
		if (src->reg.cls != C55_RC_AC || dst->reg.cls != C55_RC_AC) {
			return NULL;
		}
		const C55RegInfo *si = a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE);
		const C55RegInfo *di = a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE);
		if (!si || !si->il_var || !di || !di->il_var) {
			return NULL;
		}
		const ut32 in_pos = (bin->cond_flag == 6) ? 11 : 12; // carry / tc2
		const ut32 out_pos = (bout->cond_flag == 6) ? 11 : 12;
		const ut64 out_mask = 1ULL << out_pos;
		// the rotate-in bit, isolated from st0_55 and widened to the accumulator
		RzILOpPure *inbit = UNSIGNED(40, LOGAND(SHIFTR(IL_FALSE, VARG("st0_55"), UN(8, in_pos)), UN(16, 1)));
		RzILOpPure *rotated;
		RzILOpBool *outbit;
		if (insn->lop == C55_LOP_ROL) {
			rotated = LOGOR(SHIFTL(IL_FALSE, VARG(si->il_var), UN(6, 1)), inbit);
			outbit = MSB(VARG(si->il_var));
		} else {
			rotated = LOGOR(SHIFTR(IL_FALSE, VARG(si->il_var), UN(6, 1)),
				SHIFTL(IL_FALSE, inbit, UN(6, 0x27)));
			outbit = LSB(VARG(si->il_var));
		}
		return SEQ2(SETG(di->il_var, rotated),
			SETG("st0_55", ITE(outbit, LOGOR(VARG("st0_55"), UN(16, out_mask)), LOGAND(VARG("st0_55"), UN(16, (~out_mask) & 0xffff)))));
	}
	// mpyk / mpykr #k, ACx[, ACy]: ACy = #k * ACx, the signed constant times the
	// low 16 bits of ACx, sign-extended to the 40-bit accumulator. The rounding
	// (mpykr) variant adds 0x8000 and clears the low word.
	if (insn->lop == C55_LOP_MPYK) {
		if (insn->n_ops < 3 || !a->reg_info) {
			return NULL;
		}
		const C55Operand *imm = &insn->ops[0];
		const C55Operand *src = &insn->ops[1];
		const C55Operand *dst = &insn->ops[2];
		if (src->reg.cls != C55_RC_AC || dst->reg.cls != C55_RC_AC) {
			return NULL;
		}
		if (src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO) {
			// A half-register (ACx.h / ACx.l) multiplicand is left unlifted, as
			// the legacy lifter does -- only the whole-accumulator (low 16 bits)
			// source form lifts.
			return NULL;
		}
		const C55RegInfo *si = a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE);
		const C55RegInfo *di = a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE);
		if (!si || !si->il_var || !di || !di->il_var) {
			return NULL;
		}
		// the constant is a 16-bit signed value (the 0x1e short form supplies
		// only the low 8 bits, with the high byte zero), sign-extended to the
		// 40-bit accumulator.
		ut64 k = imm->imm & 0xffff;
		if (k & 0x8000) {
			k |= 0xffffff0000ULL;
		}
		RzILOpPure *val = MUL(UN(40, k), SIGNED(40, UNSIGNED(16, VARG(si->il_var))));
		if (insn->round) {
			val = LOGAND(ADD(val, UN(40, 0x8000)), UN(40, 0xffffff0000ULL));
		}
		return SETG(di->il_var, val);
	}
	// mack / mackr Tx, #k, ACx[, ACy]: ACy = ACx + #k * Tx, the signed constant
	// times the (sign-extended) Tx coefficient, accumulated into ACx. The
	// rounding (mackr) variant adds 0x8000 and clears the low word.
	if (insn->lop == C55_LOP_MACK) {
		if (insn->n_ops < 4 || !a->reg_info) {
			return NULL;
		}
		const C55Operand *tx = &insn->ops[0];
		const C55Operand *imm = &insn->ops[1];
		const C55Operand *src = &insn->ops[2];
		const C55Operand *dst = &insn->ops[3];
		if (tx->reg.cls != C55_RC_T || src->reg.cls != C55_RC_AC || dst->reg.cls != C55_RC_AC) {
			return NULL;
		}
		const C55RegInfo *ti = a->reg_info(tx->reg.cls, tx->reg.num, C55_SUB_NONE);
		const C55RegInfo *si = a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE);
		const C55RegInfo *di = a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE);
		if (!ti || !ti->il_var || !si || !si->il_var || !di || !di->il_var) {
			return NULL;
		}
		ut64 k = imm->imm & 0xffff;
		if (k & 0x8000) {
			k |= 0xffffff0000ULL;
		}
		RzILOpPure *val = ADD(VARG(si->il_var), MUL(SIGNED(40, VARG(ti->il_var)), UN(40, k)));
		if (insn->round) {
			val = LOGAND(ADD(val, UN(40, 0x8000)), UN(40, 0xffffff0000ULL));
		}
		return SETG(di->il_var, val);
	}
	// Memory bitwise: ACy = ACx <op> sx(Smem) for the 0xd9 / 0xda / 0xdb "and /
	// or / xor Smem, [src,] dst" forms. The 16-bit memory operand is sign-extended
	// to the 40-bit accumulator width and combined with the source accumulator.
	// The legacy lifts these only when both source and destination are
	// accumulators (it leaves T/AR operands unlifted), so the other register
	// classes return null and match the legacy by falling through.
	if (insn->lop == C55_LOP_ANDMEM || insn->lop == C55_LOP_ORMEM || insn->lop == C55_LOP_XORMEM) {
		if (insn->n_ops < 2) {
			return NULL;
		}
		const C55Operand *smem = &insn->ops[0];
		const C55Operand *dst = &insn->ops[insn->n_ops - 1];
		const C55Operand *src = insn->n_ops >= 3 ? &insn->ops[1] : dst;
		if (smem->kind != C55_OP_MEM ||
			src->kind != C55_OP_REG || src->reg.sub != C55_SUB_NONE ||
			dst->kind != C55_OP_REG || dst->reg.sub != C55_SUB_NONE) {
			return NULL;
		}
		const C55RegInfo *si = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *di = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!si || !di || !si->il_var || !di->il_var || si->width != di->width) {
			return NULL;
		}
		// The Smem base is an ARn for display but the address pointer is the
		// 23-bit XARn, so promote it before forming the effective address.
		C55Operand mp = *smem;
		if (mp.reg.cls == C55_RC_AR) {
			mp.reg.cls = C55_RC_XAR;
		}
		RzILOpPure *rd = c55_read(a, &mp);
		if (!rd) {
			return NULL;
		}
		RzILOpPure *opnd;
		if (si->width >= 40) {
			// accumulator destination: sign-extend the 16-bit memory word to the
			// 40-bit accumulator width before the bitwise op.
			RzILOpPure *rd2 = c55_read(a, &mp);
			if (!rd2) {
				rz_il_op_pure_free(rd);
				return NULL;
			}
			opnd = CAST(40, MSB(rd), rd2);
		} else {
			// 16-bit AR / T destination: operate directly on the 16-bit word.
			opnd = rd;
		}
		RzILOpPure *res = NULL;
		switch (insn->lop) {
		case C55_LOP_ANDMEM: res = LOGAND(VARG(si->il_var), opnd); break;
		case C55_LOP_ORMEM: res = LOGOR(VARG(si->il_var), opnd); break;
		case C55_LOP_XORMEM: res = LOGXOR(VARG(si->il_var), opnd); break;
		default: rz_il_op_pure_free(opnd); return NULL;
		}
		RzILOpEffect *eff = SETG(di->il_var, res);
		RzILOpEffect *post = c55_post_effect(a, &mp);
		return post ? SEQ2(eff, post) : eff;
	}
	// Dual-memory move (mov [dbl(]Xmem[)], [dbl(]Ymem[)]): store the word read
	// from Xmem (the source) into Ymem (the destination); dbl() operands move a
	// 32-bit long word. The pointer bases display as ARn but address through the
	// 23-bit XARn, so promote before forming the effective address. Each
	// operand's post-modify is sequenced after the move, Xmem then Ymem.
	if (insn->lop == C55_LOP_MOVMEM) {
		if (insn->n_ops < 2) {
			return NULL;
		}
		const C55Operand *src = &insn->ops[0]; // Xmem
		const C55Operand *dst = &insn->ops[1]; // Ymem
		if (src->kind != C55_OP_MEM || dst->kind != C55_OP_MEM) {
			return NULL;
		}
		C55Operand sp = *src;
		if (sp.reg.cls == C55_RC_AR) {
			sp.reg.cls = C55_RC_XAR;
		}
		C55Operand dp = *dst;
		if (dp.reg.cls == C55_RC_AR) {
			dp.reg.cls = C55_RC_XAR;
		}
		RzILOpPure *ld = c55_read(a, &sp);
		if (!ld) {
			return NULL;
		}
		RzILOpEffect *eff = c55_write(a, &dp, ld);
		if (!eff) {
			return NULL;
		}
		RzILOpEffect *px = c55_post_effect(a, &sp);
		if (px) {
			eff = SEQ2(eff, px);
		}
		RzILOpEffect *py = c55_post_effect(a, &dp);
		if (py) {
			eff = SEQ2(eff, py);
		}
		return eff;
	}
	// Dual-memory add / subtract into an accumulator (add / sub Xmem, Ymem,
	// ACx): ACx = sx(Xmem) +/- sx(Ymem), each Smem read as a signed 16-bit word
	// widened to the 40-bit accumulator. Post-modify of each pointer follows.
	if (insn->lop == C55_LOP_DUALADD || insn->lop == C55_LOP_DUALSUB) {
		if (insn->n_ops < 3) {
			return NULL;
		}
		const C55Operand *xm = &insn->ops[0];
		const C55Operand *ym = &insn->ops[1];
		const C55Operand *dst = &insn->ops[2];
		if (xm->kind != C55_OP_MEM || ym->kind != C55_OP_MEM ||
			dst->kind != C55_OP_REG || dst->reg.cls != C55_RC_AC || dst->reg.sub != C55_SUB_NONE) {
			return NULL;
		}
		const C55RegInfo *di = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!di || !di->il_var) {
			return NULL;
		}
		C55Operand xp = *xm;
		if (xp.reg.cls == C55_RC_AR) {
			xp.reg.cls = C55_RC_XAR;
		}
		C55Operand yp = *ym;
		if (yp.reg.cls == C55_RC_AR) {
			yp.reg.cls = C55_RC_XAR;
		}
		RzILOpPure *xa = c55_read(a, &xp), *xb = c55_read(a, &xp);
		RzILOpPure *ya = c55_read(a, &yp), *yb = c55_read(a, &yp);
		if (!xa || !xb || !ya || !yb) {
			rz_il_op_pure_free(xa);
			rz_il_op_pure_free(xb);
			rz_il_op_pure_free(ya);
			rz_il_op_pure_free(yb);
			return NULL;
		}
		RzILOpPure *sx = CAST(40, MSB(xa), xb);
		RzILOpPure *sy = CAST(40, MSB(ya), yb);
		RzILOpPure *res = (insn->lop == C55_LOP_DUALADD) ? ADD(sx, sy) : SUB(sx, sy);
		RzILOpEffect *eff = SETG(di->il_var, res);
		RzILOpEffect *px = c55_post_effect(a, &xp);
		if (px) {
			eff = SEQ2(eff, px);
		}
		RzILOpEffect *py = c55_post_effect(a, &yp);
		if (py) {
			eff = SEQ2(eff, py);
		}
		return eff;
	}
	// (neg / max / min map to SUB / CMP / CMP). All are equal-width register
	// forms; mixed-width encodings (which the legacy decoder either truncates
	// or leaves unlifted) and the equal-register short forms are left to the
	// per-arch lifter. The multiply-accumulate ops (MAC / MAS) are an exception:
	// they share the MUL op-type lifting (with the product accumulated into the
	// destination), so they fall through to the switch below.
	if (insn->lop != C55_LOP_NONE && insn->lop != C55_LOP_MAC && insn->lop != C55_LOP_MAS) {
		if (insn->n_ops < 1) {
			return NULL;
		}
		const C55Operand *src = &insn->ops[0];
		// The 0x54 register ALU forms (round / sat / addv ACx, ACy) drop the ACx
		// source when it equals the destination ACy, leaving a single operand
		// that is both source and destination.
		const C55Operand *dst = &insn->ops[insn->n_ops >= 2 ? 1 : 0];
		// neg ACx.h/.l, ACy.h/.l: a half-register negate. Read the 16-bit
		// source half, negate it, and merge-write it into the destination half
		// (preserving the rest of the accumulator), via the half-aware
		// read/write helpers. The full-register path below requires SUB_NONE.
		if (insn->lop == C55_LOP_NEG &&
			src->kind == C55_OP_REG && (src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO) &&
			dst->kind == C55_OP_REG && (dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO)) {
			RzILOpPure *sv = c55_read(a, src);
			if (!sv) {
				return NULL;
			}
			return c55_write(a, dst, SUB(UN(16, 0), sv));
		}
		if (src->kind != C55_OP_REG || src->reg.sub != C55_SUB_NONE ||
			dst->kind != C55_OP_REG || dst->reg.sub != C55_SUB_NONE ||
			src->shamt || src->sh_left || src->sh_by_reg) {
			return NULL;
		}
		const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *sri = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
		if (!dri || !dri->il_var || !sri || !sri->il_var || dri->width != sri->width) {
			return NULL;
		}
		switch (insn->lop) {
		case C55_LOP_NEG: // dst = -src
			return SETG(dri->il_var, SUB(UN(dri->width, 0), VARG(sri->il_var)));
		case C55_LOP_MAX: // dst = (src > dst) ? src : dst
			return SETG(dri->il_var,
				ITE(INV(SLE(VARG(sri->il_var), VARG(dri->il_var))),
					VARG(sri->il_var), VARG(dri->il_var)));
		case C55_LOP_MIN: // dst = (src < dst) ? src : dst
			return SETG(dri->il_var,
				ITE(AND(SLE(VARG(sri->il_var), VARG(dri->il_var)),
					    INV(EQ(VARG(sri->il_var), VARG(dri->il_var)))),
					VARG(sri->il_var), VARG(dri->il_var)));
		case C55_LOP_ABS: // dst = (src < 0) ? -src : src
			return SETG(dri->il_var,
				ITE(AND(SLE(VARG(sri->il_var), UN(dri->width, 0)),
					    INV(EQ(VARG(sri->il_var), UN(dri->width, 0)))),
					SUB(UN(dri->width, 0), VARG(sri->il_var)),
					VARG(sri->il_var)));
		case C55_LOP_ROUND: // dst = round(src) -- (src + 0x8000) with the low word cleared
			return SETG(dri->il_var,
				LOGAND(ADD(VARG(sri->il_var), UN(dri->width, 0x8000)),
					UN(dri->width, 0xffffff0000ULL)));
		case C55_LOP_SAT:
			// dst = saturate(src) to the 32-bit signed range: above 00 7FFF FFFFh
			// clamps to that maximum, below FF 8000 0000h clamps to that minimum,
			// otherwise the value passes through. The satr rounding refinement is
			// not modeled (the legacy left this form unlifted).
			return SETG(dri->il_var,
				ITE(INV(SLE(VARG(sri->il_var), UN(dri->width, 0x7fffffffULL))),
					UN(dri->width, 0x7fffffffULL),
					ITE(AND(SLE(VARG(sri->il_var), UN(dri->width, 0xff80000000ULL)),
						    INV(EQ(VARG(sri->il_var), UN(dri->width, 0xff80000000ULL)))),
						UN(dri->width, 0xff80000000ULL),
						VARG(sri->il_var))));
		case C55_LOP_ADDV: {
			// dst = dst + |src(32-16)| -- the source high word's absolute value is
			// accumulated into the destination low part (addrv's rounding is not
			// modeled; the legacy left this form unlifted).
			RzILOpPure *hi_sign = SIGNED(dri->width, CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(sri->il_var), UN(8, 16))));
			RzILOpPure *hi_neg = SIGNED(dri->width, CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(sri->il_var), UN(8, 16))));
			RzILOpPure *hi_pos = SIGNED(dri->width, CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(sri->il_var), UN(8, 16))));
			RzILOpPure *absv = ITE(MSB(hi_sign), SUB(UN(dri->width, 0), hi_neg), hi_pos);
			return SETG(dri->il_var, ADD(VARG(dri->il_var), absv));
		}
		default:
			return NULL;
		}
	}
	// Generic op_type-driven lifts for the shapes that are identical across the
	// C55 family. Anything not handled here returns NULL so the caller can fall
	// back to the legacy per-arch lifter while the migration is in progress.
	ut32 type = c55_effective_type(a, insn);
	switch (type) {
	case RZ_ANALYSIS_OP_TYPE_NOP:
		return NOP();
	case RZ_ANALYSIS_OP_TYPE_REP:
		// rpt only arms the repeat counter; it has no per-instruction data
		// effect of its own, so it lifts to a nop (matching the legacy lifter).
		return NOP();
	case RZ_ANALYSIS_OP_TYPE_LEA: {
		// amar (modify auxiliary register(s)): no memory access, only the
		// addressing modes' post-modify side effects (e.g. *arN+ increments
		// xarN), sequenced in operand order. The triple-operand form
		// (amar Xmem, Ymem, Cmem) modifies up to three pointers; a non-modifying
		// mode (plain indirect, indexed, *arN(tM), ...) contributes no effect, so
		// an all-non-modifying instruction lifts to a nop, matching the legacy.
		//
		// The C55x+ "amar Smem, xar" form instead loads the effective (word)
		// address into an extended AR register: xar = base + offset, with no
		// byte-address scaling and no memory access. It is distinguished by a
		// single memory operand followed by a register destination.
		if (insn->n_ops == 2 && insn->ops[0].kind == C55_OP_MEM &&
			insn->ops[1].kind == C55_OP_REG) {
			const C55Operand *mem = &insn->ops[0];
			const C55Operand *dst = &insn->ops[1];
			const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			if (!dri || !dri->il_var || dst->reg.sub != C55_SUB_NONE) {
				return NULL;
			}
			// Only the base+constant forms are lifted (SP/AR relative); the
			// legacy decoder leaves the DP-direct and register-modify forms
			// without IL, so decline those here too.
			RzILOpPure *base;
			if (mem->amode == C55_AM_INDEXED || mem->amode == C55_AM_CONST_IDX) {
				C55Reg br = mem->reg;
				if (br.cls == C55_RC_AR) {
					br.cls = C55_RC_XAR; // ARn is the low half of XARn
				}
				base = c55_reg_var(a, br);
				if (!base) {
					return NULL;
				}
				RzILOpPure *ea = ADD(UNSIGNED(24, base), SN(24, mem->disp));
				return SETG(dri->il_var, CAST(dri->width, IL_FALSE, ea));
			}
			return NULL;
		}
		RzILOpEffect *acc = NULL;
		for (ut8 i = 0; i < insn->n_ops; i++) {
			if (insn->ops[i].kind != C55_OP_MEM) {
				continue;
			}
			C55Operand m = insn->ops[i];
			if (m.amode == C55_AM_DIRECT) {
				// the @#k data-page direct form has no pointer side effect and
				// the legacy lifter emits no IL for it (not even a nop); match
				// that rather than claiming an empty effect.
				rz_il_op_effect_free(acc);
				return NULL;
			}
			if (m.amode == C55_AM_BITREV || m.amode == C55_AM_BITREV_SUB) {
				// the reverse-carry post-modify is a real pointer update but is
				// not modeled here; emit no IL (matching the legacy lifter)
				// rather than a misleading nop that would claim no effect.
				rz_il_op_effect_free(acc);
				return NULL;
			}
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR; // ARn is the low half of XARn
			}
			RzILOpEffect *e = c55_post_effect(a, &m);
			if (!e) {
				continue;
			}
			acc = acc ? SEQ2(acc, e) : e;
		}
		return acc ? acc : NOP();
	}
	case RZ_ANALYSIS_OP_TYPE_MOV: {
		// reg-to-reg move (sign-extended to dst width), mov #imm16, reg
		// (immediate zero-extended to dst width), or a single-data-memory
		// load / store / copy. Shifted / sub-field register forms are left to
		// the per-arch lifter.
		if (insn->n_ops < 2) {
			return NULL;
		}
		const C55Operand *src = &insn->ops[0];
		const C55Operand *dst = &insn->ops[1];
		// mmap(@reg) (memory-mapped register access) aliases the register
		// itself, just as in the push/pop MMR handling. "mov src, mmap(@reg)"
		// writes the source into the register; "mov mmap(@reg), dst" reads it.
		// The value is width-adjusted (zero-extended or truncated) to bridge a
		// 16-bit half and the register's own width.
		if (dst->kind == C55_OP_MEM && dst->amode == C55_AM_MMR && src->kind == C55_OP_REG &&
			!dst->shamt && !dst->mem_round) {
			const C55RegInfo *ri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			if (!ri || !ri->il_var) {
				return NULL;
			}
			bool s_half = src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO;
			const C55RegInfo *si = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
			ut32 sw = s_half ? 16 : (si ? si->width : 16);
			RzILOpPure *v = c55_read(a, src);
			if (sw > ri->width) {
				v = CAST(ri->width, IL_FALSE, v);
			} else if (sw < ri->width) {
				v = UNSIGNED(ri->width, v);
			}
			return SETG(ri->il_var, v);
		}
		if (src->kind == C55_OP_MEM && src->amode == C55_AM_MMR && dst->kind == C55_OP_REG &&
			!src->shamt && !src->mem_round) {
			const C55RegInfo *ri = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
			if (!ri || !ri->il_var) {
				return NULL;
			}
			bool d_half = dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO;
			const C55RegInfo *di = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			ut32 dw = d_half ? 16 : (di ? di->width : 16);
			RzILOpPure *v = VARG(ri->il_var);
			if (ri->width > dw) {
				v = CAST(dw, IL_FALSE, v);
			} else if (ri->width < dw) {
				v = UNSIGNED(dw, v);
			}
			return c55_write(a, dst, v);
		}
		// mov [uns](Smem) << #sh, ACx: load the memory word, extend it to the
		// accumulator width (zero-extended for uns(), else sign-extended) and
		// shift it left by the immediate count before storing. A register shift
		// count, rounding or high/low-byte form falls back.
		if (src->kind == C55_OP_MEM && dst->kind == C55_OP_REG && dst->reg.sub == C55_SUB_NONE &&
			src->shamt && src->sh_left && !src->sh_by_reg && !src->sh_mem_reg_set &&
			!src->mem_round && src->byte_sel != 1 && src->byte_sel != 2) {
			const C55RegInfo *ri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			if (!ri || !ri->il_var || ri->width < 24) {
				return NULL;
			}
			switch (src->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
			case C55_AM_ABS16:
				break;
			default:
				return NULL;
			}
			C55Operand m = *src;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			RzILOpPure *mem = c55_read(a, &m);
			if (!mem) {
				return NULL;
			}
			RzILOpPure *ext = src->uns ? UNSIGNED(ri->width, mem) : SIGNED(ri->width, mem);
			RzILOpPure *sh = SHIFTL(IL_FALSE, ext, UN(8, (ut64)src->shamt));
			RzILOpEffect *wr = SETG(ri->il_var, sh);
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(wr, post) : wr;
		}
		// Smem load / copy (memory -> register) and store (register -> memory).
		if (src->kind == C55_OP_MEM && dst->kind == C55_OP_REG) {
			return c55_mem_move(a, dst, src, true);
		}
		if (dst->kind == C55_OP_MEM && src->kind == C55_OP_REG) {
			return c55_mem_move(a, src, dst, false);
		}
		// mov Smem, Smem (memory-to-memory copy): load the source word (or
		// byte) and store it to the destination, applying both operands'
		// post-modify side effects. Both operands must use the shared mover's
		// addressing modes and the same access width; shifted, rounded and
		// high/low-byte forms fall back.
		if (src->kind == C55_OP_MEM && dst->kind == C55_OP_MEM &&
			!src->shamt && !dst->shamt && !src->sh_mem_reg_set && !dst->sh_mem_reg_set &&
			!src->mem_round && !dst->mem_round &&
			src->byte_sel != 1 && src->byte_sel != 2 && dst->byte_sel != 1 && dst->byte_sel != 2 &&
			(src->byte_sel == 3) == (dst->byte_sel == 3)) {
			const C55Operand *mm[2] = { src, dst };
			bool ok = true;
			for (int mi = 0; mi < 2; mi++) {
				switch (mm[mi]->amode) {
				case C55_AM_INDIRECT:
				case C55_AM_POSTINC:
				case C55_AM_POSTDEC:
				case C55_AM_IDXREG:
				case C55_AM_POSTADD:
				case C55_AM_POSTSUB:
				case C55_AM_INDEXED:
				case C55_AM_ABSOLUTE:
				case C55_AM_CONST_IDX:
				case C55_AM_CONST_IDX_PRE:
				case C55_AM_ABS16:
					break;
				default:
					ok = false;
				}
			}
			if (!ok) {
				return NULL;
			}
			C55Operand sm = *src, dm = *dst;
			if (sm.reg.cls == C55_RC_AR) {
				sm.reg.cls = C55_RC_XAR;
			}
			if (dm.reg.cls == C55_RC_AR) {
				dm.reg.cls = C55_RC_XAR;
			}
			if (sm.byte_sel == 3) {
				sm.access = 8;
				dm.access = 8;
			}
			RzILOpPure *v = c55_read(a, &sm);
			if (!v) {
				return NULL;
			}
			RzILOpEffect *wr = c55_write(a, &dm, v);
			if (!wr) {
				return NULL;
			}
			RzILOpEffect *ps = c55_post_effect(a, &sm);
			if (ps) {
				wr = SEQ2(wr, ps);
			}
			RzILOpEffect *pd = c55_post_effect(a, &dm);
			if (pd) {
				wr = SEQ2(wr, pd);
			}
			return wr;
		}
		// mov #imm, Smem (immediate -> memory store, e.g. the byte() form): the
		// immediate is materialised as a 16-bit word and truncated to the access
		// width, then stored at the (post-modify-free) effective address. Only
		// the addressing modes the shared mover supports are lifted.
		if (dst->kind == C55_OP_MEM && src->kind == C55_OP_IMM &&
			!dst->shamt && !dst->sh_mem_reg_set && !dst->mem_round && dst->byte_sel != 1 && dst->byte_sel != 2) {
			switch (dst->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
				break;
			default:
				return NULL;
			}
			C55Operand m = *dst;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			RzILOpPure *addr = c55_ea(a, &m);
			if (!addr) {
				return NULL;
			}
			ut32 aw = m.access ? m.access : 16;
			RzILOpPure *v = UN(16, src->imm & 0xffff);
			if (aw != 16) {
				v = UNSIGNED(aw, v);
			}
			RzILOpEffect *wr = STOREW(addr, v);
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(wr, post) : wr;
		}
		// mov gr4, hi(ACx): write the source's low 16 bits into the accumulator
		// high word (bits 31-16), preserving the rest. The legacy lifter shifts
		// by a 6-bit count, reproduced here for byte-exactness.
		if (dst->kind == C55_OP_REG && dst->reg.sub == C55_SUB_HI &&
			src->kind == C55_OP_REG && src->reg.sub == C55_SUB_NONE &&
			!src->shamt && !src->sh_left && !src->sh_by_reg) {
			const C55RegInfo *hdri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			if (!hdri || !hdri->il_var) {
				return NULL;
			}
			RzILOpPure *sv = c55_read(a, src);
			if (!sv) {
				return NULL;
			}
			const C55RegInfo *ssri = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
			if (ssri && ssri->width > 16) {
				sv = CAST(16, IL_FALSE, sv);
			}
			RzILOpPure *wide = UNSIGNED(hdri->width, sv);
			return SETG(hdri->il_var,
				LOGOR(LOGAND(VARG(hdri->il_var), UN(hdri->width, 0xff0000ffffULL)),
					SHIFTL(IL_FALSE, wide, UN(6, 16))));
		}
		// mov #imm, ACx.h / ACx.l: write the immediate into the accumulator
		// high or low word, preserving the rest (the 0x7b #k4 and 0xac #k16
		// register-short / immediate moves into a sub-register). The legacy
		// lifter shifts the high word by a 6-bit count and zero-extends the
		// immediate to 16 bits; reproduced here for byte-exactness.
		if (src->kind == C55_OP_IMM && !src->addr && !src->neg_imm &&
			!src->sh_left && !src->shamt && dst->kind == C55_OP_REG &&
			(dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO)) {
			const C55RegInfo *sdri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			if (!sdri || !sdri->il_var) {
				return NULL;
			}
			RzILOpPure *wide = UNSIGNED(sdri->width, UN(16, src->imm & 0xffff));
			if (dst->reg.sub == C55_SUB_HI) {
				return SETG(sdri->il_var,
					LOGOR(LOGAND(VARG(sdri->il_var), UN(sdri->width, 0xff0000ffffULL)),
						SHIFTL(IL_FALSE, wide, UN(6, 16))));
			}
			return SETG(sdri->il_var,
				LOGOR(LOGAND(VARG(sdri->il_var), UN(sdri->width, 0xffffff0000ULL)), wide));
		}
		// mov -#k, ACx.l/.h or mov -#k, reg (the 0x7b/0x3e negated-immediate
		// forms): the operand already carries the two's-complement value, so it
		// is written directly as a 16-bit value into a sub-register half
		// (merged) or truncated to the destination register width.
		if (src->kind == C55_OP_IMM && src->neg_imm && !src->addr &&
			!src->sh_left && !src->shamt && dst->kind == C55_OP_REG) {
			if (dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO) {
				return c55_write(a, dst, UN(16, src->imm & 0xffff));
			}
			if (dst->reg.sub == C55_SUB_NONE) {
				const C55RegInfo *ndri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
				if (!ndri || !ndri->il_var) {
					return NULL;
				}
				return SETG(ndri->il_var, UN(ndri->width, src->imm));
			}
		}
		// mov srcreg, ACx.l / ACx.h: write the source's low 16 bits into the
		// accumulator low or high word, preserving the rest. A half source is
		// read as its 16-bit value; a whole register wider than a word is
		// truncated to 16 bits. c55_write performs the read-modify-write merge
		// into the destination half.
		if (dst->kind == C55_OP_REG &&
			(dst->reg.sub == C55_SUB_LO || dst->reg.sub == C55_SUB_HI) &&
			src->kind == C55_OP_REG &&
			!src->shamt && !src->sh_left && !src->sh_by_reg) {
			RzILOpPure *sv = c55_read(a, src);
			if (!sv) {
				return NULL;
			}
			const C55RegInfo *ssri = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
			if (src->reg.sub == C55_SUB_NONE && ssri && ssri->width > 16) {
				sv = CAST(16, IL_FALSE, sv); // truncate a whole register to the half width
			}
			return c55_write(a, dst, sv);
		}
		if (dst->kind != C55_OP_REG || dst->reg.sub != C55_SUB_NONE) {
			return NULL;
		}
		const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		if (!dri || !dri->il_var) {
			return NULL;
		}
		if (src->kind == C55_OP_IMM && !src->addr) {
			if (src->sh_left && src->shamt_hex) {
				// mov #k16 << #sh (opcode 0x75): the legacy leaves this form
				// unlifted, so decline and fall through to the (null) legacy IL.
				return NULL;
			}
			if (src->neg_imm) {
				// mov -#k, dst (opcode 0x3e): unlifted by the legacy decoder.
				return NULL;
			}
			ut64 v = src->imm;
			if (src->sh_left && src->shamt) {
				// A left-shifted immediate (mov #k16 << #16): the field is a
				// signed constant, sign-extended before the shift; the UN below
				// truncates back to the destination width.
				if (src->width > 0 && src->width < 64 && (v & (1ULL << (src->width - 1)))) {
					v |= ~((1ULL << src->width) - 1);
				}
				v <<= src->shamt;
			}
			return SETG(dri->il_var, UN(dri->width, v));
		}
		if (src->kind == C55_OP_REG && src->reg.sub == C55_SUB_NONE &&
			!src->shamt && !src->sh_left && !src->sh_by_reg) {
			const C55RegInfo *sri = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
			if (!sri || !sri->il_var) {
				return NULL;
			}
			RzILOpPure *v = VARG(sri->il_var);
			if (dri->width > sri->width) {
				// Widening register move. Address/pointer registers (AR, XAR)
				// hold unsigned values and are zero-extended; data registers
				// (AC, T) are sign-extended.
				if (src->reg.cls == C55_RC_AR || src->reg.cls == C55_RC_XAR) {
					v = UNSIGNED(dri->width, v);
				} else {
					v = SIGNED(dri->width, v);
				}
			} else if (dri->width < sri->width) {
				// narrowing register move (e.g. mov ACx, sp): keep the low bits.
				v = UNSIGNED(dri->width, v);
			}
			return SETG(dri->il_var, v);
		}
		if (src->kind == C55_OP_REG && (src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO) &&
			!src->shamt && !src->sh_left && !src->sh_by_reg) {
			// mov hi(ACx), dst / mov ACx.l, dst: the 16-bit high or low word,
			// sign-extended to the destination width (c55_read selects the half).
			RzILOpPure *v = c55_read(a, src);
			if (!v) {
				return NULL;
			}
			if (dri->width > 16) {
				v = SIGNED(dri->width, v);
			} else if (dri->width < 16) {
				rz_il_op_pure_free(v);
				return NULL;
			}
			return SETG(dri->il_var, v);
		}
		return NULL;
	}
	case RZ_ANALYSIS_OP_TYPE_XCHG: {
		// swap rX, rY: exchange via the XOR-swap idiom (X^=Y; Y^=X; X^=Y).
		// swapp exchanges two consecutive pairs, swap4 four (X..X+3 <-> Y..Y+3).
		if (insn->n_ops < 2 || !a->reg_info) {
			return NULL;
		}
		const C55Operand *x = &insn->ops[0];
		const C55Operand *y = &insn->ops[1];
		if (x->kind != C55_OP_REG || y->kind != C55_OP_REG) {
			return NULL;
		}
		int npairs = insn->quad ? 4 : (insn->both ? 2 : 1);
		const C55RegInfo *xi[4], *yi[4];
		for (int p = 0; p < npairs; p++) {
			xi[p] = a->reg_info(x->reg.cls, (ut8)(x->reg.num + p), C55_SUB_NONE);
			yi[p] = a->reg_info(y->reg.cls, (ut8)(y->reg.num + p), C55_SUB_NONE);
			if (!xi[p] || !xi[p]->il_var || !yi[p] || !yi[p]->il_var) {
				return NULL;
			}
		}
		RzILOpEffect *eff[12];
		for (int p = 0; p < npairs; p++) {
			eff[p * 3 + 0] = SETG(xi[p]->il_var, LOGXOR(VARG(xi[p]->il_var), VARG(yi[p]->il_var)));
			eff[p * 3 + 1] = SETG(yi[p]->il_var, LOGXOR(VARG(yi[p]->il_var), VARG(xi[p]->il_var)));
			eff[p * 3 + 2] = SETG(xi[p]->il_var, LOGXOR(VARG(xi[p]->il_var), VARG(yi[p]->il_var)));
		}
		if (npairs == 1) {
			return SEQ3(eff[0], eff[1], eff[2]);
		}
		if (npairs == 2) {
			return SEQ6(eff[0], eff[1], eff[2], eff[3], eff[4], eff[5]);
		}
		return SEQN(12, eff[0], eff[1], eff[2], eff[3], eff[4], eff[5],
			eff[6], eff[7], eff[8], eff[9], eff[10], eff[11]);
	}
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB: {
		// dst <op>= src. A full-register source is sign-extended to the dst
		// width (add/sub ACx, ACy or add/sub Tx, ACy); a plain (unshifted,
		// unsigned) immediate source is zero-extended to the dst width
		// (add/sub k4, dst). Sub-field (.h/.l), shifted, and signed immediate
		// sources are left to the per-arch lifter.
		if (insn->n_ops < 2) {
			return NULL;
		}
		const C55Operand *src = &insn->ops[0];
		const C55Operand *dst = &insn->ops[1];
		// add/sub dbl(Lmem), ACx, ACy and sub ACx, dbl(Lmem), ACy (opcode
		// 0x8d): a 32-bit long-word memory operand, sign-extended to the
		// accumulator width (zero-extended under uns()). When the memory is the
		// first operand the result is ACy = ACx +/- dbl(Lmem); the reversed
		// SUB form (memory second) is ACy = dbl(Lmem) - ACx (spru374g p572-573).
		if (insn->n_ops == 3) {
			int mi = -1;
			for (int i = 0; i < 2; i++) {
				if (insn->ops[i].kind == C55_OP_MEM && insn->ops[i].dbl) {
					mi = i;
					break;
				}
			}
			if (mi >= 0 && !(mi == 1 && type != RZ_ANALYSIS_OP_TYPE_SUB)) {
				const C55Operand *mem = &insn->ops[mi];
				const C55Operand *acx = &insn->ops[mi == 0 ? 1 : 0];
				const C55Operand *acy = &insn->ops[2];
				if (acx->kind != C55_OP_REG || acx->reg.sub != C55_SUB_NONE ||
					acy->kind != C55_OP_REG || acy->reg.sub != C55_SUB_NONE ||
					mem->byte_sel || mem->shamt || mem->sh_mem_reg_set || mem->mem_round) {
					return NULL;
				}
				switch (mem->amode) {
				case C55_AM_INDIRECT:
				case C55_AM_POSTINC:
				case C55_AM_POSTDEC:
				case C55_AM_IDXREG:
				case C55_AM_POSTADD:
				case C55_AM_POSTSUB:
				case C55_AM_INDEXED:
				case C55_AM_ABSOLUTE:
				case C55_AM_CONST_IDX:
				case C55_AM_CONST_IDX_PRE:
				case C55_AM_ABS16:
					break;
				default:
					return NULL;
				}
				const C55RegInfo *xri = a->reg_info ? a->reg_info(acx->reg.cls, acx->reg.num, C55_SUB_NONE) : NULL;
				const C55RegInfo *yri = a->reg_info ? a->reg_info(acy->reg.cls, acy->reg.num, C55_SUB_NONE) : NULL;
				if (!xri || !xri->il_var || !yri || !yri->il_var) {
					return NULL;
				}
				C55Operand m = *mem;
				if (m.reg.cls == C55_RC_AR) {
					m.reg.cls = C55_RC_XAR;
				}
				RzILOpPure *dv = c55_read(a, &m);
				if (!dv) {
					return NULL;
				}
				ut32 lw = m.access ? m.access : 16;
				if (yri->width > lw) {
					dv = m.uns ? UNSIGNED(yri->width, dv) : SIGNED(yri->width, dv);
				} else if (yri->width < lw) {
					dv = UNSIGNED(yri->width, dv);
				}
				RzILOpPure *av = VARG(xri->il_var);
				if (yri->width > xri->width) {
					av = SIGNED(yri->width, av);
				} else if (yri->width < xri->width) {
					av = UNSIGNED(yri->width, av);
				}
				RzILOpPure *res = (mi == 1)
					? SUB(dv, av) // ACy = dbl - ACx
					: (type == RZ_ANALYSIS_OP_TYPE_ADD ? ADD(av, dv) : SUB(av, dv)); // ACy = ACx +/- dbl
				RzILOpEffect *wr = SETG(yri->il_var, res);
				RzILOpEffect *post = c55_post_effect(a, &m);
				return post ? SEQ2(wr, post) : wr;
			}
		}
		// sub ACx.<sub>, Smem, ACy.<sub> (reverse memory-source subtract on a
		// 16-bit slice): ACy.<sub> = Smem - ACx.<sub> (spru374g p666, reversed
		// form). A .L destination merges [15:0]; a .H destination sign-extends
		// through the guard. Memory post-modify side effects follow.
		if (type == RZ_ANALYSIS_OP_TYPE_SUB && insn->n_ops == 3 &&
			insn->ops[0].kind == C55_OP_REG &&
			(insn->ops[0].reg.sub == C55_SUB_HI || insn->ops[0].reg.sub == C55_SUB_LO) &&
			insn->ops[1].kind == C55_OP_MEM && insn->ops[2].kind == C55_OP_REG &&
			(insn->ops[2].reg.sub == C55_SUB_HI || insn->ops[2].reg.sub == C55_SUB_LO) &&
			!insn->ops[1].byte_sel && !insn->ops[1].shamt &&
			!insn->ops[1].sh_mem_reg_set && !insn->ops[1].mem_round) {
			const C55Operand *areg = &insn->ops[0];
			const C55Operand *mem = &insn->ops[1];
			const C55Operand *dh = &insn->ops[2];
			switch (mem->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
			case C55_AM_ABS16:
				break;
			default:
				return NULL;
			}
			C55Operand m = *mem;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			RzILOpPure *mv = c55_read(a, &m);
			if (!mv) {
				return NULL;
			}
			if ((m.access ? m.access : 16) != 16) {
				mv = CAST(16, IL_FALSE, mv);
			}
			RzILOpPure *res16 = SUB(mv, c55_read(a, areg)); // ACy = Smem - ACx
			RzILOpEffect *wr = c55_write_half_arith(a, dh, res16);
			if (!wr) {
				return NULL;
			}
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(wr, post) : wr;
		}
		// add Smem, [src,] dst (memory-source add): dst = src + extend(Smem),
		// with src == dst for the two-operand form. The memory word is
		// sign-extended to the destination width (zero-extended under uns());
		// a narrower register source is sign-extended, matching the register
		// add and memory-load conventions. Memory post-modify side effects
		// follow. sub is order-sensitive and bitwise memory sources have their
		// own extension rules, so both are left to the per-arch lifter.
		if (type == RZ_ANALYSIS_OP_TYPE_ADD && (insn->n_ops == 2 || insn->n_ops == 3) &&
			src->kind == C55_OP_MEM && !src->byte_sel && !src->shamt &&
			!src->sh_mem_reg_set && !src->mem_round) {
			const C55Operand *addend = &insn->ops[1];
			const C55Operand *dreg = &insn->ops[insn->n_ops - 1];
			bool addend_half = addend->kind == C55_OP_REG &&
				(addend->reg.sub == C55_SUB_HI || addend->reg.sub == C55_SUB_LO);
			if (addend->kind != C55_OP_REG || (addend->reg.sub != C55_SUB_NONE && !addend_half) ||
				dreg->kind != C55_OP_REG || dreg->reg.sub != C55_SUB_NONE) {
				return NULL;
			}
			switch (src->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
			case C55_AM_ABS16:
				break;
			default:
				return NULL;
			}
			const C55RegInfo *ari = a->reg_info ? a->reg_info(addend->reg.cls, addend->reg.num, C55_SUB_NONE) : NULL;
			const C55RegInfo *dri2 = a->reg_info ? a->reg_info(dreg->reg.cls, dreg->reg.num, C55_SUB_NONE) : NULL;
			if (!ari || !ari->il_var || !dri2 || !dri2->il_var) {
				return NULL;
			}
			C55Operand m = *src;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			RzILOpPure *mv = c55_read(a, &m);
			if (!mv) {
				return NULL;
			}
			ut32 mw = m.access ? m.access : 16;
			if (dri2->width > mw) {
				mv = m.uns ? UNSIGNED(dri2->width, mv) : SIGNED(dri2->width, mv);
			} else if (dri2->width < mw) {
				mv = UNSIGNED(dri2->width, mv);
			}
			RzILOpPure *av;
			if (addend_half) {
				av = SIGNED(dri2->width, c55_read(a, addend)); // 16-bit slice sign-extended
			} else {
				av = VARG(ari->il_var);
				if (dri2->width > ari->width) {
					av = SIGNED(dri2->width, av);
				} else if (dri2->width < ari->width) {
					av = UNSIGNED(dri2->width, av);
				}
			}
			RzILOpEffect *wr = SETG(dri2->il_var, ADD(av, mv));
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(wr, post) : wr;
		}
		// Half-register add/sub (the 0xc4 / 0x7b .l/.h forms): operate on the
		// 16-bit accumulator slice. Per SWPU104 1.5.1 a .L destination updates
		// [15:0] and a .H destination updates [39:16] (sign-extended through the
		// guard). Forms: 2-op "add/sub #k, ACx.l/.h" (dst op= k), 3-op
		// "add/sub #k, ACx.l/.h, ACy.l/.h" (dst = src op k) and 2-op
		// "add/sub ACx.l/.h, ACy.l/.h" (dst = dst op src).
		{
			const C55Operand *dh = &insn->ops[insn->n_ops - 1];
			bool dst_half = dh->kind == C55_OP_REG &&
				(dh->reg.sub == C55_SUB_HI || dh->reg.sub == C55_SUB_LO);
			if (dst_half && (insn->n_ops == 2 || insn->n_ops == 3)) {
				RzILOpPure *sv = NULL, *bv = NULL;
				if (src->kind == C55_OP_IMM && !src->addr && !src->sh_left && !src->shamt) {
					const C55Operand *sreg = (insn->n_ops == 3) ? &insn->ops[1] : dh;
					if (sreg->kind == C55_OP_REG &&
						(sreg->reg.sub == C55_SUB_HI || sreg->reg.sub == C55_SUB_LO)) {
						sv = c55_read(a, sreg);
						bv = UN(16, (ut64)src->imm & 0xffff);
					}
				} else if (src->kind == C55_OP_REG &&
					(src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO) &&
					!src->shamt && !src->sh_left && !src->sh_by_reg) {
					if (insn->n_ops == 2) {
						sv = c55_read(a, dh); // dst = dst op src
						bv = c55_read(a, src);
					} else {
						const C55Operand *s2 = &insn->ops[1];
						if (s2->kind == C55_OP_REG &&
							(s2->reg.sub == C55_SUB_HI || s2->reg.sub == C55_SUB_LO)) {
							sv = c55_read(a, src); // dst = src op src2
							bv = c55_read(a, s2);
						}
					}
				}
				if (sv && bv) {
					RzILOpPure *res16 = (type == RZ_ANALYSIS_OP_TYPE_ADD) ? ADD(sv, bv) : SUB(sv, bv);
					return c55_write_half_arith(a, dh, res16);
				}
				rz_il_op_pure_free(sv);
				rz_il_op_pure_free(bv);
				return NULL;
			}
		}
		// add/sub #k, Smem (memory-destination read-modify-write): Smem = Smem
		// +/- k. The memory word is read, the immediate applied at the access
		// width and the result stored back, with any post-modify side effect.
		if (insn->n_ops == 2 && src->kind == C55_OP_IMM && !src->addr &&
			!src->shamt && !src->sh_left && dst->kind == C55_OP_MEM &&
			!dst->byte_sel && !dst->shamt && !dst->sh_mem_reg_set && !dst->mem_round) {
			switch (dst->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
			case C55_AM_ABS16:
				break;
			default:
				return NULL;
			}
			C55Operand m = *dst;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			ut32 mw = m.access ? m.access : 16;
			RzILOpPure *cur = c55_read(a, &m);
			if (!cur) {
				return NULL;
			}
			RzILOpPure *kv = UN(mw, (ut64)src->imm);
			RzILOpPure *res = (type == RZ_ANALYSIS_OP_TYPE_ADD) ? ADD(cur, kv) : SUB(cur, kv);
			RzILOpEffect *st = c55_write(a, &m, res);
			if (!st) {
				return NULL;
			}
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(st, post) : st;
		}
		if (src->kind == C55_OP_IMM && !src->imm_signed && !src->addr &&
			!src->shamt && !src->sh_left && !src->sh_by_reg &&
			dst->kind == C55_OP_REG && dst->reg.sub == C55_SUB_NONE) {
			const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			if (!dri || !dri->il_var) {
				return NULL;
			}
			RzILOpPure *res = (type == RZ_ANALYSIS_OP_TYPE_ADD)
				? ADD(VARG(dri->il_var), UN(dri->width, src->imm))
				: SUB(VARG(dri->il_var), UN(dri->width, src->imm));
			return SETG(dri->il_var, res);
		}
		if (dst->kind != C55_OP_REG || dst->reg.sub != C55_SUB_NONE ||
			src->kind != C55_OP_REG || src->reg.sub != C55_SUB_NONE ||
			src->shamt || src->sh_left || src->sh_by_reg) {
			return NULL;
		}
		const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *sri = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
		if (!dri || !dri->il_var || !sri || !sri->il_var || dri->width < sri->width) {
			return NULL;
		}
		RzILOpPure *s = VARG(sri->il_var);
		if (dri->width > sri->width) {
			s = SIGNED(dri->width, s);
		}
		RzILOpPure *res = (type == RZ_ANALYSIS_OP_TYPE_ADD)
			? ADD(VARG(dri->il_var), s)
			: SUB(VARG(dri->il_var), s);
		return SETG(dri->il_var, res);
	}
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_NOT: {
		// Bitwise accumulator ops on equal-width full registers: and/or/xor are
		// dst <op>= src, not is dst = ~src. Narrow (sub-width) sources and
		// sub-field (.h/.l) operands use different bit semantics (operating on a
		// 16-bit slice and merging) and are left to the per-arch lifter.
		if (insn->n_ops < 2) {
			return NULL;
		}
		// btst @#k, ACx.l/.h, TCy: test bit k of the (16-bit half of the)
		// source register and write it to the TCy status bit in st0_55. ops[0]
		// is the bit number, ops[1] the source register, ops[2] the TC flag.
		if (type == RZ_ANALYSIS_OP_TYPE_AND && insn->n_ops >= 3 &&
			insn->ops[0].kind == C55_OP_IMM && insn->ops[0].is_bit &&
			insn->ops[1].kind == C55_OP_REG &&
			insn->ops[2].kind == C55_OP_COND && insn->ops[2].cond_is_flag) {
			RzILOpPure *rv = c55_read(a, &insn->ops[1]);
			if (!rv) {
				return NULL;
			}
			unsigned k = (unsigned)(insn->ops[0].imm & 0x3f);
			RzILOpBool *bitval = LSB(SHIFTR(IL_FALSE, rv, UN(6, (ut64)k)));
			ut64 tcbit = (insn->ops[2].cond_flag & 1) ? 0x1000 : 0x2000; // tc2 : tc1
			return SETG("st0_55",
				ITE(bitval,
					LOGOR(VARG("st0_55"), UN(16, tcbit)),
					LOGAND(VARG("st0_55"), UN(16, (~tcbit) & 0xffff))));
		}
		const C55Operand *src = &insn->ops[0];
		const C55Operand *dst = &insn->ops[1];
		// or/and/xor Smem, ACx.<sub>, ACy.<sub> (memory-source bitwise into an
		// accumulator half): ACy.<sub> = ACx.<sub> <op> Smem on the 16-bit
		// slice. A .L destination merges [15:0]; a .H destination writes
		// [31:16]. Memory post-modify side effects follow.
		if (type != RZ_ANALYSIS_OP_TYPE_NOT && insn->n_ops == 3 &&
			src->kind == C55_OP_MEM && insn->ops[1].kind == C55_OP_REG &&
			insn->ops[2].kind == C55_OP_REG &&
			(insn->ops[2].reg.sub == C55_SUB_HI || insn->ops[2].reg.sub == C55_SUB_LO) &&
			!src->byte_sel && !src->shamt && !src->sh_mem_reg_set && !src->mem_round) {
			const C55Operand *sreg = &insn->ops[1];
			const C55Operand *dh = &insn->ops[2];
			switch (src->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
			case C55_AM_ABS16:
				break;
			default:
				return NULL;
			}
			const C55RegInfo *sri = a->reg_info ? a->reg_info(sreg->reg.cls, sreg->reg.num, C55_SUB_NONE) : NULL;
			if (!sri || !sri->il_var) {
				return NULL;
			}
			C55Operand m = *src;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			RzILOpPure *mv = c55_read(a, &m);
			if (!mv) {
				return NULL;
			}
			if ((m.access ? m.access : 16) != 16) {
				mv = CAST(16, IL_FALSE, mv);
			}
			RzILOpPure *sv = c55_read(a, sreg);
			bool s_half = sreg->reg.sub == C55_SUB_HI || sreg->reg.sub == C55_SUB_LO;
			if (!s_half && sri->width > 16) {
				sv = CAST(16, IL_FALSE, sv);
			}
			RzILOpPure *r16 = type == RZ_ANALYSIS_OP_TYPE_AND ? LOGAND(sv, mv)
				: type == RZ_ANALYSIS_OP_TYPE_OR          ? LOGOR(sv, mv)
									  : LOGXOR(sv, mv);
			RzILOpEffect *wr = c55_write(a, dh, r16);
			if (!wr) {
				return NULL;
			}
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(wr, post) : wr;
		}
		// or/and/xor Smem, src, dst (memory-source 3-operand bitwise into a
		// full accumulator): dst = src <op> zero-extend(Smem). The 16-bit
		// memory word is zero-extended to the destination width; a 16-bit
		// register source (AR/T or a half) is likewise zero-extended, while a
		// full-accumulator source is used as-is (SWPU104 6.6.1). Memory
		// post-modify side effects follow.
		if (type != RZ_ANALYSIS_OP_TYPE_NOT && insn->n_ops == 3 &&
			src->kind == C55_OP_MEM && insn->ops[1].kind == C55_OP_REG &&
			insn->ops[2].kind == C55_OP_REG && insn->ops[2].reg.sub == C55_SUB_NONE &&
			!src->byte_sel && !src->shamt && !src->sh_mem_reg_set && !src->mem_round) {
			const C55Operand *sreg = &insn->ops[1];
			const C55Operand *dreg = &insn->ops[2];
			switch (src->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
			case C55_AM_ABS16:
				break;
			default:
				return NULL;
			}
			const C55RegInfo *sri = a->reg_info ? a->reg_info(sreg->reg.cls, sreg->reg.num, C55_SUB_NONE) : NULL;
			const C55RegInfo *dri = a->reg_info ? a->reg_info(dreg->reg.cls, dreg->reg.num, C55_SUB_NONE) : NULL;
			if (!sri || !sri->il_var || !dri || !dri->il_var) {
				return NULL;
			}
			C55Operand m = *src;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			RzILOpPure *mem16 = c55_read(a, &m);
			if (!mem16) {
				return NULL;
			}
			RzILOpPure *mv = UNSIGNED(dri->width, mem16);
			RzILOpPure *sv;
			if (sreg->reg.sub == C55_SUB_NONE && sri->width == dri->width) {
				sv = VARG(sri->il_var);
			} else {
				RzILOpPure *s16 = c55_read(a, sreg);
				if (sreg->reg.sub == C55_SUB_NONE && sri->width > 16) {
					s16 = CAST(16, IL_FALSE, s16);
				}
				sv = UNSIGNED(dri->width, s16);
			}
			RzILOpPure *r = type == RZ_ANALYSIS_OP_TYPE_AND ? LOGAND(sv, mv)
				: type == RZ_ANALYSIS_OP_TYPE_OR        ? LOGOR(sv, mv)
									: LOGXOR(sv, mv);
			RzILOpEffect *wr = SETG(dri->il_var, r);
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(wr, post) : wr;
		}
		// (Smem op= imm). Only the addressing modes the shared effective-address
		// primitive supports are lifted; the byte-select and shifted forms fall
		// back. NOT has a single source and is excluded.
		if (type != RZ_ANALYSIS_OP_TYPE_NOT && dst->kind == C55_OP_MEM && src->kind == C55_OP_IMM &&
			!dst->shamt && !dst->sh_mem_reg_set && !dst->mem_round && dst->byte_sel != 1 && dst->byte_sel != 2) {
			switch (dst->amode) {
			case C55_AM_INDIRECT:
			case C55_AM_POSTINC:
			case C55_AM_POSTDEC:
			case C55_AM_IDXREG:
			case C55_AM_POSTADD:
			case C55_AM_POSTSUB:
			case C55_AM_INDEXED:
			case C55_AM_ABSOLUTE:
			case C55_AM_CONST_IDX:
			case C55_AM_CONST_IDX_PRE:
				break;
			default:
				return NULL;
			}
			C55Operand m = *dst;
			if (m.reg.cls == C55_RC_AR) {
				m.reg.cls = C55_RC_XAR;
			}
			RzILOpPure *la = c55_ea(a, &m);
			RzILOpPure *sa = c55_ea(a, &m);
			if (!la || !sa) {
				rz_il_op_pure_free(la);
				rz_il_op_pure_free(sa);
				return NULL;
			}
			ut32 aw = m.access ? m.access : 16;
			RzILOpPure *k = UN(16, src->imm & 0xffff);
			if (aw != 16) {
				k = UNSIGNED(aw, k);
			}
			RzILOpPure *res = type == RZ_ANALYSIS_OP_TYPE_AND ? LOGAND(LOADW(aw, la), k) : LOGOR(LOADW(aw, la), k);
			RzILOpEffect *wr = STOREW(sa, res);
			RzILOpEffect *post = c55_post_effect(a, &m);
			return post ? SEQ2(wr, post) : wr;
		}
		// C55x+ 16-bit slice bitwise ops (the 0x75 and/or/xor src, dst forms):
		// when an operand is a sub-register half, or the two registers differ in
		// width (e.g. xor Tx, ACy / xor ACx.l, Ty), the operation runs on 16-bit
		// low-word slices and the 16-bit result is merged back -- accumulator
		// destinations preserve bits 39-16, 16-bit destinations are written
		// whole. NOT is excluded (single source, handled below).
		if (type != RZ_ANALYSIS_OP_TYPE_NOT && src->kind == C55_OP_REG && dst->kind == C55_OP_REG &&
			!src->shamt && !src->sh_left && !src->sh_by_reg && a->reg_info) {
			const C55RegInfo *sr = a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE);
			const C55RegInfo *dr = a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE);
			bool src_half = src->reg.sub == C55_SUB_HI || src->reg.sub == C55_SUB_LO;
			bool dst_half = dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO;
			if (sr && dr && sr->il_var && dr->il_var &&
				(src_half || dst_half || sr->width != dr->width)) {
				RzILOpPure *sv = src_half ? c55_read(a, src)
							  : (sr->width > 16 ? CAST(16, IL_FALSE, VARG(sr->il_var)) : VARG(sr->il_var));
				RzILOpPure *dv = dst_half ? c55_read(a, dst)
							  : (dr->width > 16 ? CAST(16, IL_FALSE, VARG(dr->il_var)) : VARG(dr->il_var));
				if (!sv || !dv) {
					rz_il_op_pure_free(sv);
					rz_il_op_pure_free(dv);
					return NULL;
				}
				RzILOpPure *res = type == RZ_ANALYSIS_OP_TYPE_AND ? LOGAND(dv, sv)
					: type == RZ_ANALYSIS_OP_TYPE_OR          ? LOGOR(dv, sv)
										  : LOGXOR(dv, sv);
				if (dr->width > 16) {
					if (dst->reg.sub == C55_SUB_HI) {
						// high-word destination (bits 31-16): preserve bits 39-32
						// and 15-0, and shift the 16-bit result up by 16.
						ut64 keep = (dr->width >= 64 ? ~0ULL : ((1ULL << dr->width) - 1)) & ~((ut64)0xffff << 16);
						return SETG(dr->il_var, LOGOR(LOGAND(VARG(dr->il_var), UN(dr->width, keep)), SHIFTL(IL_FALSE, UNSIGNED(dr->width, res), UN(6, 16))));
					}
					// low-word destination (bits 15-0): preserve bits 39-16.
					ut64 keep = (dr->width >= 64 ? ~0ULL : ((1ULL << dr->width) - 1)) & ~(ut64)0xffff;
					return SETG(dr->il_var, LOGOR(LOGAND(VARG(dr->il_var), UN(dr->width, keep)), UNSIGNED(dr->width, res)));
				}
				return SETG(dr->il_var, res);
			}
		}
		// not ACx.half, ACy.half (the 0x75 .h/.l forms): invert the 16-bit
		// slice and merge it back into the destination half. The slice handler
		// above excludes NOT (single source), so it is handled here.
		if (type == RZ_ANALYSIS_OP_TYPE_NOT && src->kind == C55_OP_REG && dst->kind == C55_OP_REG &&
			(dst->reg.sub == C55_SUB_HI || dst->reg.sub == C55_SUB_LO) &&
			!src->shamt && !src->sh_left && !src->sh_by_reg) {
			RzILOpPure *sv = c55_read(a, src); // 16-bit for a half source
			if (!sv) {
				return NULL;
			}
			const C55RegInfo *sr = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
			if (src->reg.sub == C55_SUB_NONE && sr && sr->width > 16) {
				sv = CAST(16, IL_FALSE, sv); // truncate a whole source to the half width
			}
			return c55_write(a, dst, LOGNOT(sv));
		}
		// not <src>, ARx/Tx: dst = ~src into a 16-bit register, the source read
		// as its 16-bit value (a .h/.l half, or a whole register truncated to
		// 16 bits). The half-destination and equal-width full-register forms are
		// handled above; this covers e.g. not ACx.l, ARy.
		if (type == RZ_ANALYSIS_OP_TYPE_NOT && src->kind == C55_OP_REG && dst->kind == C55_OP_REG &&
			dst->reg.sub == C55_SUB_NONE && !src->shamt && !src->sh_left && !src->sh_by_reg) {
			const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
			if (dri && dri->il_var && dri->width == 16) {
				RzILOpPure *sv = c55_read(a, src);
				if (!sv) {
					return NULL;
				}
				const C55RegInfo *sr = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
				if (src->reg.sub == C55_SUB_NONE && sr && sr->width > 16) {
					sv = CAST(16, IL_FALSE, sv); // truncate a whole source to 16 bits
				}
				return SETG(dri->il_var, LOGNOT(sv));
			}
		}
		if (dst->kind != C55_OP_REG || dst->reg.sub != C55_SUB_NONE ||
			src->kind != C55_OP_REG || src->reg.sub != C55_SUB_NONE ||
			src->shamt || src->sh_left || src->sh_by_reg) {
			return NULL;
		}
		const C55RegInfo *dri = a->reg_info ? a->reg_info(dst->reg.cls, dst->reg.num, C55_SUB_NONE) : NULL;
		const C55RegInfo *sri = a->reg_info ? a->reg_info(src->reg.cls, src->reg.num, C55_SUB_NONE) : NULL;
		if (!dri || !dri->il_var || !sri || !sri->il_var || dri->width != sri->width) {
			return NULL;
		}
		if (type == RZ_ANALYSIS_OP_TYPE_NOT) {
			return SETG(dri->il_var, LOGNOT(VARG(sri->il_var)));
		}
		RzILOpPure *res =
			type == RZ_ANALYSIS_OP_TYPE_AND ? LOGAND(VARG(dri->il_var), VARG(sri->il_var)) : type == RZ_ANALYSIS_OP_TYPE_OR ? LOGOR(VARG(dri->il_var), VARG(sri->il_var))
																	: LOGXOR(VARG(dri->il_var), VARG(sri->il_var));
		return SETG(dri->il_var, res);
	}
	case RZ_ANALYSIS_OP_TYPE_PUSH:
	case RZ_ANALYSIS_OP_TYPE_POP: {
		// Single-word stack op: SP is a 16-bit word pointer, the stack lives in
		// data memory at byte address SP<<1. Push pre-decrements then stores;
		// pop loads then post-increments. Accumulator / dbl(ACx) (32-bit, two
		// words) move two words. The register-pair forms (pop/psh rX, rY) move
		// each register in turn, in operand order, with its own SP adjustment.
		if (insn->n_ops < 1) {
			return NULL;
		}
		if (insn->both && insn->n_ops < 2) {
			// popboth / pshboth move a register *pair* in one op via a single
			// operand; the single-register lift below would be wrong, so leave
			// them unlifted (matching the legacy decoder). The two-operand
			// "psh/pop rX, rY" forms (also flagged .both) fall through to the
			// per-register loop below, which models them correctly.
			return NULL;
		}
		// Build the per-register effect sequence; for the two-register pair
		// forms this is the two single-register sequences concatenated.
		RzILOpEffect *acc = NULL;
		for (ut8 i = 0; i < insn->n_ops && i < 2; i++) {
			const C55Operand *o = &insn->ops[i];
			bool is_sub = o->kind == C55_OP_REG &&
				(o->reg.sub == C55_SUB_LO || o->reg.sub == C55_SUB_HI || o->reg.sub == C55_SUB_GUARD);
			C55Reg reg;
			if (o->kind == C55_OP_REG && o->reg.sub == C55_SUB_NONE) {
				reg = o->reg;
			} else if (is_sub) {
				// psh / pop ACx.l / ACx.h / ACx.g: a sub-register half.
				reg = o->reg;
			} else if (o->kind == C55_OP_MEM && o->amode == C55_AM_MMR) {
				// pop / psh mmap(@reg): the memory-mapped register moves through
				// the stack exactly as a plain register of its own width.
				reg = o->reg;
			} else {
				return NULL;
			}
			const C55RegInfo *ri = a->reg_info ? a->reg_info(reg.cls, reg.num, C55_SUB_NONE) : NULL;
			if (!ri || !ri->il_var) {
				return NULL;
			}
			RzILOpEffect *step = NULL;
			if (is_sub) {
				// Sub-register stack op: a single word carries the 16-bit half
				// (or, for .g, the 8-bit guard, zero-extended to a word). psh
				// pre-decrements SP by one word and stores; pop loads the word
				// and merges it back into the half via c55_write's
				// read-modify-write. SP advances by one word.
				if (o->dbl) {
					return NULL;
				}
				if (type == RZ_ANALYSIS_OP_TYPE_PUSH) {
					RzILOpPure *hv = c55_read(a, o);
					if (!hv) {
						return NULL;
					}
					step = SEQ2(
						SETG("sp", SUB(VARG("sp"), UN(16, 1))),
						STOREW(MUL(UNSIGNED(24, VARG("sp")), UN(24, 2)), UNSIGNED(16, hv)));
				} else {
					RzILOpEffect *wr = c55_write(a, o, LOADW(16, MUL(UNSIGNED(24, VARG("sp")), UN(24, 2))));
					if (!wr) {
						return NULL;
					}
					step = SEQ2(wr, SETG("sp", ADD(VARG("sp"), UN(16, 1))));
				}
			} else if (ri->width == 40) {
				// Accumulator stack op: 32 bits (two words) move through the
				// stack. psh stores the low 32 bits; pop reloads them while
				// preserving the guard byte. SP advances by two words.
				if (type == RZ_ANALYSIS_OP_TYPE_PUSH) {
					step = SEQ2(
						SETG("sp", SUB(VARG("sp"), UN(16, 2))),
						STOREW(MUL(UNSIGNED(24, VARG("sp")), UN(24, 2)), UNSIGNED(32, VARG(ri->il_var))));
				} else {
					step = SEQ2(
						SETG(ri->il_var, LOGOR(LOGAND(VARG(ri->il_var), UN(40, 0xff00000000ULL)), UNSIGNED(40, LOADW(32, MUL(UNSIGNED(24, VARG("sp")), UN(24, 2)))))),
						SETG("sp", ADD(VARG("sp"), UN(16, 2))));
				}
			} else if (o->dbl) {
				// psh / pop dbl(xarN): the extended pointer register stored as a
				// 32-bit double word (two words). psh stores the zero-extended
				// pointer; pop reloads its low bits. SP advances by two words.
				if (type == RZ_ANALYSIS_OP_TYPE_PUSH) {
					step = SEQ2(
						SETG("sp", SUB(VARG("sp"), UN(16, 2))),
						STOREW(MUL(UNSIGNED(24, VARG("sp")), UN(24, 2)), UNSIGNED(32, VARG(ri->il_var))));
				} else {
					step = SEQ2(
						SETG(ri->il_var, UNSIGNED(ri->width, LOADW(32, MUL(UNSIGNED(24, VARG("sp")), UN(24, 2))))),
						SETG("sp", ADD(VARG("sp"), UN(16, 2))));
				}
			} else {
				if (ri->width != 16) {
					return NULL;
				}
				if (type == RZ_ANALYSIS_OP_TYPE_PUSH) {
					step = SEQ2(
						SETG("sp", SUB(VARG("sp"), UN(16, 1))),
						STOREW(MUL(UNSIGNED(24, VARG("sp")), UN(24, 2)), VARG(ri->il_var)));
				} else {
					step = SEQ2(
						SETG(ri->il_var, LOADW(16, MUL(UNSIGNED(24, VARG("sp")), UN(24, 2)))),
						SETG("sp", ADD(VARG("sp"), UN(16, 1))));
				}
			}
			acc = acc ? SEQ2(acc, step) : step;
		}
		return acc;
	}
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		// A direct branch / call lifts as an unconditional transfer to the
		// resolved (pc-relative or absolute) target.
		return JMP(UN(24, c55_branch_target(insn, pc) & 0xffffff));
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL: {
		// Register-indirect branch / call: jump to the (24-bit) address held in
		// the operand register. The call's return-address push is modelled in
		// the analysis stack metadata rather than the IL, matching the legacy
		// lifter.
		if (insn->n_ops < 1 || insn->ops[0].kind != C55_OP_REG) {
			return NULL;
		}
		const C55RegInfo *ri = a->reg_info ? a->reg_info(insn->ops[0].reg.cls, insn->ops[0].reg.num, insn->ops[0].reg.sub) : NULL;
		if (!ri || !ri->il_var) {
			return NULL;
		}
		return JMP(UNSIGNED(24, VARG(ri->il_var)));
	}
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_CJMP: {
		// bcc: take the branch to the resolved target when the predicate holds,
		// else fall through. Flag-based predicates fall back to the per-arch lifter.
		const C55Operand *cond = NULL;
		for (ut8 i = 0; i < insn->n_ops; i++) {
			if (insn->ops[i].kind == C55_OP_COND) {
				cond = &insn->ops[i];
				break;
			}
		}
		RzILOpPure *pred = cond ? c55_cond_pred(a, cond, insn->uns_all) : NULL;
		if (!pred) {
			return NULL;
		}
		return BRANCH(pred, JMP(UN(24, c55_branch_target(insn, pc) & 0xffffff)), NOP());
	}
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_CRET: {
		// ret / reti / retcc: the return address sits on top of the stack,
		// where the matching call left it (two words, the low 24 bits holding
		// the PC). It is read first, then SP is popped by two words, then
		// control transfers to it. SP is a 16-bit word pointer and the stack
		// lives at byte address SP<<1, matching the push/pop model. reti also
		// reloads status from the stack on the hardware; that state restore is
		// not modelled (only the control transfer is). The conditional retcc
		// performs the return when its predicate holds and otherwise falls
		// through to the next instruction.
		RzILOpEffect *doret = SEQ3(
			SETL("ret_addr", LOADW(24, MUL(UNSIGNED(24, VARG("sp")), UN(24, 2)))),
			SETG("sp", ADD(VARG("sp"), UN(16, 2))),
			JMP(VARL("ret_addr")));
		if (type == RZ_ANALYSIS_OP_TYPE_CRET) {
			const C55Operand *cond = NULL;
			for (ut8 i = 0; i < insn->n_ops; i++) {
				if (insn->ops[i].kind == C55_OP_COND) {
					cond = &insn->ops[i];
					break;
				}
			}
			RzILOpPure *pred = cond ? c55_cond_pred(a, cond, insn->uns_all) : NULL;
			if (!pred) {
				rz_il_op_effect_free(doret);
				return NULL;
			}
			return BRANCH(pred, doret, NOP());
		}
		return doret;
	}
	case RZ_ANALYSIS_OP_TYPE_MUL: {
		// Multiply, optionally accumulating. c55_mac_effect handles the register /
		// memory single forms (mpy, mpym, mac{m}, mas{m}, sqrm / sqam / sqsm); the
		// dual "::" forms are dispatched on insn->dual before this switch.
		// The 0x54 register ALU forms (mpy / sqr / sqa / sqs ACx, ACy) drop the
		// ACx multiplicand when it equals the destination ACy, leaving a single
		// operand; the operation then squares / multiplies that accumulator by
		// itself, so feed it to both multiplier inputs.
		if (insn->n_ops >= 1 && insn->ops[0].kind == C55_OP_IMM) {
			// The multiply-by-constant forms (mpyk / mack with a leading #k) are
			// not lifted: c55_mac_effect models the multiplicand as a register or
			// memory operand, and the dedicated MPYK lifter does not yet cover the
			// C55x+ sub-register (ACx.h / ACx.l) source selection. Leave them
			// unlifted (as the legacy lifter does) rather than emit wrong IL.
			return NULL;
		}
		if (insn->n_ops == 1) {
			C55Operand self[2] = { insn->ops[0], insn->ops[0] };
			return c55_mac_effect(a, self, 2, insn->lop, insn->round, insn->shift16, insn->square, insn->side_load);
		}
		return c55_mac_effect(a, insn->ops, insn->n_ops, insn->lop, insn->round, insn->shift16, insn->square, insn->side_load);
	}
	default:
		return NULL;
	}
}

static void c55_fmt_reg(RzStrBuf *sb, const C55ArchDesc *a, const C55Reg *r) {
	const C55RegInfo *ri = a->reg_info ? a->reg_info(r->cls, r->num, r->sub) : NULL;
	const char *name = (ri && ri->name) ? ri->name : "";
	if (a->arch == C55_ARCH_C55X && (r->sub == C55_SUB_HI || r->sub == C55_SUB_LO)) {
		// C55x renders the accumulator halves as hi(acN) / lo(acN); the C55x+
		// algebraic syntax uses the .h / .l suffix handled below.
		rz_strbuf_appendf(sb, "%s(%s)", r->sub == C55_SUB_HI ? "hi" : "lo", name);
		return;
	}
	rz_strbuf_append(sb, name);
	switch (r->sub) {
	case C55_SUB_LO: rz_strbuf_append(sb, ".l"); break;
	case C55_SUB_HI: rz_strbuf_append(sb, ".h"); break;
	case C55_SUB_GUARD: rz_strbuf_append(sb, ".g"); break;
	default: break;
	}
}

static void c55_fmt_mem(RzStrBuf *sb, const C55ArchDesc *a, const C55Operand *m) {
	if (a->arch == C55_ARCH_C54X) {
		// C54x addressing syntax differs from C55x (AR0-indexed *arN+0, circular
		// *arN+%, bit-reverse *arN+0B). Render it self-contained and return; the
		// C55x logic below never runs for C54x.
		switch (m->amode) {
		case C55_AM_DIRECT:
			rz_strbuf_appendf(sb, "@0x%" PFMT32x, (ut32)m->disp & 0x7f);
			return;
		case C55_AM_MMR: {
			// a memory-mapped register resolved to its name (pshm/popm/ldm/stm);
			// chip-specific peripheral MMRs with no core name render numerically.
			const C55RegInfo *ri = a->reg_info ? a->reg_info(m->reg.cls, m->reg.num, m->reg.sub) : NULL;
			if (ri) {
				c55_fmt_reg(sb, a, &m->reg);
			} else {
				rz_strbuf_appendf(sb, "0x%" PFMT64x, m->abs_addr & 0xffff);
			}
			return;
		}
		case C55_AM_ABSOLUTE:
			rz_strbuf_appendf(sb, "*(0x%" PFMT64x ")", m->abs_addr & 0xffff);
			return;
		case C55_AM_ABS16:
			// *(lk): a 16-bit absolute data address (the long word lands in disp).
			rz_strbuf_appendf(sb, "*(0x%" PFMT32x ")", (ut32)m->disp & 0xffff);
			return;
		default:
			break;
		}
		rz_strbuf_append(sb, "*");
		if (m->amode == C55_AM_PREINC || m->amode == C55_AM_CONST_IDX_PRE) {
			rz_strbuf_append(sb, "+");
		}
		c55_fmt_reg(sb, a, &m->reg);
		switch (m->amode) {
		case C55_AM_POSTINC: rz_strbuf_append(sb, "+"); break;
		case C55_AM_POSTDEC: rz_strbuf_append(sb, "-"); break;
		case C55_AM_POSTADD: rz_strbuf_append(sb, "+0"); break;
		case C55_AM_POSTSUB: rz_strbuf_append(sb, "-0"); break;
		case C55_AM_BITREV: rz_strbuf_append(sb, "+0B"); break;
		case C55_AM_BITREV_SUB: rz_strbuf_append(sb, "-0B"); break;
		case C55_AM_CONST_IDX:
		case C55_AM_CONST_IDX_PRE:
			rz_strbuf_appendf(sb, "(0x%" PFMT32x ")", (ut32)m->disp & 0xffff);
			break;
		default: break;
		}
		if (m->circular) {
			rz_strbuf_append(sb, "%");
		}
		return;
	}
	if (m->uns) {
		rz_strbuf_append(sb, "uns(");
	}
	if (m->byte_sel == 1) {
		rz_strbuf_append(sb, "high_byte(");
	} else if (m->byte_sel == 2) {
		rz_strbuf_append(sb, "low_byte(");
	} else if (m->byte_sel == 3) {
		rz_strbuf_append(sb, "byte(");
	}
	if (m->amode == C55_AM_ABSOLUTE) {
		if (a->arch == C55_ARCH_C55X) {
			rz_strbuf_appendf(sb, "*(0x%06" PFMT64X ")", m->abs_addr);
		} else {
			rz_strbuf_appendf(sb, "*(#0x%" PFMT64x ")", m->abs_addr);
		}
	} else if (m->amode == C55_AM_MMR) {
		// memory-mapped register access: mmap(@<reg>).
		rz_strbuf_append(sb, "mmap(@");
		c55_fmt_reg(sb, a, &m->reg);
		rz_strbuf_append(sb, ")");
	} else if (m->amode == C55_AM_DIRECT) {
		// DP/SP-relative direct: @#k (the data-page direct address).
		rz_strbuf_appendf(sb, "@#0x%x", (unsigned)((ut32)m->disp & 0x7f));
	} else if (m->amode == C55_AM_ABS16) {
		rz_strbuf_appendf(sb, "abs16(0x%x)", (unsigned)((ut32)m->disp & 0xffff));
	} else if (m->amode == C55_AM_INDEXED && m->reg.cls == C55_RC_SP) {
		// SP-relative direct: the C54x/C55x syntax is *sp(#Nh) (uppercase hex with
		// an 'h' suffix); the C55x+ algebraic syntax is *sp(#0xN).
		if (a->arch == C55_ARCH_C55X) {
			rz_strbuf_appendf(sb, "*sp(#%Xh)", (unsigned)(m->disp & 0xffff));
		} else {
			rz_strbuf_appendf(sb, "*sp(#0x%x)", (unsigned)(m->disp & 0xffff));
		}
	} else {
		rz_strbuf_append(sb, "*");
		if (m->amode == C55_AM_PREINC || m->amode == C55_AM_CONST_IDX_PRE) {
			rz_strbuf_append(sb, "+");
		} else if (m->amode == C55_AM_PREDEC) {
			rz_strbuf_append(sb, "-");
		}
		if (m->amode == C55_AM_POSTADD || m->amode == C55_AM_POSTSUB ||
			m->amode == C55_AM_BITREV || m->amode == C55_AM_BITREV_SUB) {
			rz_strbuf_append(sb, "(");
		}
		c55_fmt_reg(sb, a, &m->reg);
		switch (m->amode) {
		case C55_AM_POSTINC: rz_strbuf_append(sb, "+"); break;
		case C55_AM_POSTDEC: rz_strbuf_append(sb, "-"); break;
		case C55_AM_INDEXED: rz_strbuf_appendf(sb, "(short(#0x%x))", (unsigned)(m->disp & 0xffff)); break;
		case C55_AM_CONST_IDX:
		case C55_AM_CONST_IDX_PRE:
			// The C54x/C55x syntax renders the long const-index in hex as
			// (0xN); the C55x+ algebraic syntax renders it as (#decimal).
			if (a->arch == C55_ARCH_C55X) {
				rz_strbuf_appendf(sb, "(0x%x)", (unsigned)(m->disp & 0xffff));
			} else {
				rz_strbuf_appendf(sb, "(#%u)", (unsigned)(m->disp & 0xffff));
			}
			break;
		case C55_AM_IDXREG:
			rz_strbuf_append(sb, "(");
			c55_fmt_reg(sb, a, &m->index);
			rz_strbuf_append(sb, ")");
			break;
		case C55_AM_IDXSCALE:
			// *arN(tM<<#1): the index register scaled left by one.
			rz_strbuf_append(sb, "(");
			c55_fmt_reg(sb, a, &m->index);
			rz_strbuf_append(sb, "<<#1)");
			break;
		case C55_AM_XAR15:
			// *arN(xar15): coefficient addressing through XAR15.
			rz_strbuf_append(sb, "(xar15)");
			break;
		case C55_AM_POSTADD:
			// the CDP coefficient form *(cdp+t0) has no spaces around the
			// operator, unlike the spaced C55x AR post-indexed form.
			rz_strbuf_append(sb, m->reg.cls == C55_RC_CDP ? "+" : (a->arch == C55_ARCH_C55X ? " + " : "+"));
			c55_fmt_reg(sb, a, &m->index);
			rz_strbuf_append(sb, ")");
			break;
		case C55_AM_POSTSUB:
			rz_strbuf_append(sb, m->reg.cls == C55_RC_CDP ? "-" : (a->arch == C55_ARCH_C55X ? " - " : "-"));
			c55_fmt_reg(sb, a, &m->index);
			rz_strbuf_append(sb, ")");
			break;
		case C55_AM_BITREV:
			// reverse-carry post-increment by t0: the index prints with a "b"
			// (bit-reverse) suffix -> *(arN + t0b).
			rz_strbuf_append(sb, a->arch == C55_ARCH_C55X ? " + " : "+");
			c55_fmt_reg(sb, a, &m->index);
			rz_strbuf_append(sb, "b)");
			break;
		case C55_AM_BITREV_SUB:
			rz_strbuf_append(sb, a->arch == C55_ARCH_C55X ? " - " : "-");
			c55_fmt_reg(sb, a, &m->index);
			rz_strbuf_append(sb, "b)");
			break;
		default: break;
		}
	}
	if (m->byte_sel) {
		rz_strbuf_append(sb, ")");
	}
	if (m->uns) {
		rz_strbuf_append(sb, ")");
	}
}

// Render one sub-MAC of a dual "::" instruction: "<mn>[r][40] Smem, Cmem, ACx [>> #16]"
// (c55_fmt_mem emits each operand's own uns() wrapper), or "amar Smem" for an amar sub1.
static void c55_fmt_dual_sub(RzStrBuf *sb, const C55ArchDesc *a, const C55Operand *mem,
	const C55Operand *cmem, const C55Operand *dst, C55LiftOp lop, bool amar,
	bool round, bool m40, bool shift16) {
	if (amar) {
		rz_strbuf_append(sb, "amar ");
		c55_fmt_mem(sb, a, mem);
		return;
	}
	rz_strbuf_append(sb, (lop == C55_LOP_MAC) ? "mac" : (lop == C55_LOP_MAS) ? "mas"
										 : "mpy");
	if (round) {
		rz_strbuf_append(sb, "r");
	}
	if (m40) {
		rz_strbuf_append(sb, "40");
	}
	rz_strbuf_append(sb, " ");
	c55_fmt_mem(sb, a, mem);
	rz_strbuf_append(sb, ", ");
	c55_fmt_mem(sb, a, cmem);
	rz_strbuf_append(sb, ", ");
	c55_fmt_reg(sb, a, &dst->reg);
	if (shift16) {
		rz_strbuf_append(sb, " >> #16");
	}
}

char *c55_format(const C55ArchDesc *a, const C55Insn *insn) {
	if (!a || !insn) {
		return NULL;
	}
	if (insn->parallel_pair) {
		// "||" parallel pair: re-decode and format the two sub-instructions, then
		// join them with " || " (the order reversed for the legacy hash 0xF0/0xF1
		// forms).
		C55Insn s1, s2;
		if (!c55_decode(a, insn->par_bytes + insn->par_off1, insn->size - insn->par_off1, &s1) ||
			!c55_decode(a, insn->par_bytes + insn->par_off2, insn->size - insn->par_off2, &s2)) {
			return NULL;
		}
		char *a1 = c55_format(a, &s1);
		char *a2 = c55_format(a, &s2);
		if (!a1 || !a2) {
			free(a1);
			free(a2);
			return NULL;
		}
		char *res = insn->par_swap ? rz_str_newf("%s || %s", a2, a1) : rz_str_newf("%s || %s", a1, a2);
		free(a1);
		free(a2);
		return res;
	}
	const char *mn = a->mnemonic ? a->mnemonic(insn->id) : NULL;
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	if (insn->dual) {
		// dual "::" MAC: render the two sub-MACs joined by " :: ". Sub1 is the
		// ops[0..2] (Xmem, Cmem, ACx) triple (or an amar over ops[0]); sub2 is
		// the ops[3..5] (Ymem, Cmem, ACy) triple.
		c55_fmt_dual_sub(&sb, a, &insn->ops[0], &insn->ops[1], &insn->ops[2],
			insn->lop, insn->amar1, insn->round, insn->m40, insn->shift1);
		rz_strbuf_append(&sb, " :: ");
		c55_fmt_dual_sub(&sb, a, &insn->ops[3], &insn->ops[4], &insn->ops[5],
			insn->lop2, false, insn->round, insn->m40, insn->shift2);
		return rz_strbuf_drain_nofree(&sb);
	}
	if (insn->diff_form) {
		// "<mnem> ACc, ACd, ACa, ACb, [pair(]trn[)]": ops [0]=ACc [1]=ACd [2]=ACa
		// [3]=ACb [4]=trn. The max/min-diff (non-d) variants wrap trn in pair().
		const char *mn = a->mnemonic ? a->mnemonic(insn->id) : NULL;
		rz_strbuf_append(&sb, mn ? mn : "invalid");
		rz_strbuf_append(&sb, " ");
		for (int i = 0; i < 4; i++) {
			c55_fmt_reg(&sb, a, &insn->ops[i].reg);
			rz_strbuf_append(&sb, ", ");
		}
		if (insn->diff_pair) {
			rz_strbuf_append(&sb, "pair(");
		}
		c55_fmt_reg(&sb, a, &insn->ops[4].reg);
		if (insn->diff_pair) {
			rz_strbuf_append(&sb, ")");
		}
		return rz_strbuf_drain_nofree(&sb);
	}
	if (insn->mant_nexp) {
		// "mant ACa, ACb :: nexp ACa, ACc": ops [0]=ACa (shared) [1]=ACb [2]=ACc.
		rz_strbuf_append(&sb, "mant ");
		c55_fmt_reg(&sb, a, &insn->ops[0].reg);
		rz_strbuf_append(&sb, ", ");
		c55_fmt_reg(&sb, a, &insn->ops[1].reg);
		rz_strbuf_append(&sb, " :: nexp ");
		c55_fmt_reg(&sb, a, &insn->ops[0].reg);
		rz_strbuf_append(&sb, ", ");
		c55_fmt_reg(&sb, a, &insn->ops[2].reg);
		return rz_strbuf_drain_nofree(&sb);
	}
	if (insn->mac_store) {
		// C55x 0x87 parallel dual-MAC with a parallel hi-word store. Three
		// shapes, distinguished by operand count / kinds:
		//   mpym/macm/masm[r] [t3=]Xmem, Tx, ACy :: mov hi(ACx << t2), Ymem
		//     ops [0]=Xmem [1]=Tx [2]=ACy [3]=Ymem [4]=ACx
		//   add/sub Xmem << #16, ACx, ACy :: mov hi(ACy << t2), Ymem
		//     ops [0]=Xmem [1]=ACx [2]=ACy [3]=Ymem
		//   mov Xmem << #16, ACy :: mov hi(ACx << t2), Ymem
		//     ops [0]=Xmem [1]=ACy [2]=Ymem [3]=ACx
		const char *mn = a->mnemonic ? a->mnemonic(insn->id) : NULL;
		rz_strbuf_append(&sb, mn ? mn : "invalid");
		if (insn->round) {
			rz_strbuf_append(&sb, "r");
		}
		rz_strbuf_append(&sb, " ");
		if (insn->n_ops >= 5) {
			if (insn->side_load) {
				rz_strbuf_append(&sb, "t3=");
			}
			c55_fmt_mem(&sb, a, &insn->ops[0]);
			rz_strbuf_append(&sb, ", ");
			c55_fmt_reg(&sb, a, &insn->ops[1].reg);
			rz_strbuf_append(&sb, ", ");
			c55_fmt_reg(&sb, a, &insn->ops[2].reg);
			rz_strbuf_append(&sb, " :: mov hi(");
			c55_fmt_reg(&sb, a, &insn->ops[4].reg);
			rz_strbuf_append(&sb, " << t2), ");
			c55_fmt_mem(&sb, a, &insn->ops[3]);
		} else if (insn->n_ops == 4 && insn->ops[2].kind == C55_OP_REG) {
			c55_fmt_mem(&sb, a, &insn->ops[0]);
			rz_strbuf_append(&sb, " << #16, ");
			c55_fmt_reg(&sb, a, &insn->ops[1].reg);
			rz_strbuf_append(&sb, ", ");
			c55_fmt_reg(&sb, a, &insn->ops[2].reg);
			rz_strbuf_append(&sb, " :: mov hi(");
			c55_fmt_reg(&sb, a, &insn->ops[2].reg);
			rz_strbuf_append(&sb, " << t2), ");
			c55_fmt_mem(&sb, a, &insn->ops[3]);
		} else {
			c55_fmt_mem(&sb, a, &insn->ops[0]);
			rz_strbuf_append(&sb, " << #16, ");
			c55_fmt_reg(&sb, a, &insn->ops[1].reg);
			rz_strbuf_append(&sb, " :: mov hi(");
			c55_fmt_reg(&sb, a, &insn->ops[3].reg);
			rz_strbuf_append(&sb, " << t2), ");
			c55_fmt_mem(&sb, a, &insn->ops[2]);
		}
		return rz_strbuf_drain_nofree(&sb);
	}
	if (insn->mac_mov) {
		// MAC :: parallel load: "macm/masm[r] [t3=]Xmem, Tx, ACx :: mov Ymem << #16, ACy".
		// ops: [0]=Xmem [1]=Tx [2]=ACx [3]=Ymem [4]=ACy.
		const char *mn = a->mnemonic ? a->mnemonic(insn->id) : NULL;
		rz_strbuf_append(&sb, mn ? mn : "invalid");
		if (insn->round) {
			rz_strbuf_append(&sb, "r");
		}
		rz_strbuf_append(&sb, " ");
		if (insn->side_load) {
			rz_strbuf_append(&sb, "t3=");
		}
		c55_fmt_mem(&sb, a, &insn->ops[0]);
		rz_strbuf_append(&sb, ", ");
		c55_fmt_reg(&sb, a, &insn->ops[1].reg);
		rz_strbuf_append(&sb, ", ");
		c55_fmt_reg(&sb, a, &insn->ops[2].reg);
		rz_strbuf_append(&sb, " :: mov ");
		c55_fmt_mem(&sb, a, &insn->ops[3]);
		rz_strbuf_append(&sb, " << #16, ");
		c55_fmt_reg(&sb, a, &insn->ops[4].reg);
		return rz_strbuf_drain_nofree(&sb);
	}
	if (insn->parallel) {
		rz_strbuf_append(&sb, "|| ");
	}
	rz_strbuf_append(&sb, mn ? mn : "invalid");
	if (insn->fract) {
		// the fractional-mode variant appends 'f' before any 'r' (mpyk -> mpykf,
		// mpykf -> mpykfr)
		rz_strbuf_append(&sb, "f");
	}
	if (insn->round) {
		// the rounding variant appends 'r' to the mnemonic (mpy -> mpyr, ...)
		rz_strbuf_append(&sb, "r");
	}
	if (insn->m40) {
		// the 40-bit (M40) variant appends '40', after any 'r' (mpyr -> mpyr40)
		rz_strbuf_append(&sb, "40");
	}
	if (insn->uns_all) {
		// whole-operation unsigned appends 'u' (mpym -> mpymu); the operands carry
		// uns for the lift but are rendered without per-operand uns() wrappers.
		rz_strbuf_append(&sb, "u");
	}
	for (ut8 i = 0; i < insn->n_ops; i++) {
		const C55Operand *op = &insn->ops[i];
		if (op->elide_if_eq_prev && i > 0) {
			// the optional ACy defaults to ACx: omit it (and its separator)
			// when it names the same register as the preceding operand.
			const C55Operand *prev = &insn->ops[i - 1];
			if (op->kind == C55_OP_REG && prev->kind == C55_OP_REG &&
				op->reg.cls == prev->reg.cls && op->reg.num == prev->reg.num &&
				op->reg.sub == prev->reg.sub) {
				continue;
			}
		}
		rz_strbuf_append(&sb, i == 0 ? " " : (op->space_join ? " " : (op->shl_join ? " << " : (op->qual_join ? " || " : ", "))));
		if (i == 0 && insn->side_load) {
			// memory-MAC side-load: the first (Smem) operand is also written
			// into T3, rendered as "t3=" (C55x) / "t3 = " (C55x+) before it.
			rz_strbuf_append(&sb, a->arch == C55_ARCH_C55X ? "t3=" : "t3 = ");
		}
		if (op->raw) {
			// a verbatim operand string (e.g. the un-decoded "Baddr" of btstp).
			rz_strbuf_append(&sb, op->raw);
			continue;
		}
		switch (op->kind) {
		case C55_OP_REG: {
			int nclose = 0;
			if (op->wrap_uns) {
				rz_strbuf_append(&sb, "uns(");
				nclose++;
			}
			if (op->wrap_round) {
				rz_strbuf_append(&sb, "rnd(");
				nclose++;
			}
			if (op->wrap_half == 1) {
				rz_strbuf_append(&sb, "hi(");
				nclose++;
			} else if (op->wrap_half == 2) {
				rz_strbuf_append(&sb, "lo(");
				nclose++;
			}
			if (op->dbl) {
				rz_strbuf_append(&sb, "dbl(");
			}
			c55_fmt_reg(&sb, a, &op->reg);
			if (op->dbl) {
				rz_strbuf_append(&sb, ")");
			}
			if (op->sh_by_reg) {
				rz_strbuf_append(&sb, " << ");
				c55_fmt_reg(&sb, a, &op->index);
			} else if (op->sh_left && op->shamt) {
				rz_strbuf_appendf(&sb, " << #%d", op->shamt);
			}
			while (nclose-- > 0) {
				rz_strbuf_append(&sb, ")");
			}
			break;
		}
		case C55_OP_IMM: {
			// The C55x (non-plus) disassembler prints immediates as uppercase
			// hex without the '#' prefix that the C55x+ / C54x syntax uses.
			bool c55x = (a->arch == C55_ARCH_C55X);
			const char *ip = c55x ? "" : "#";
			if (op->is_bit) {
				// A bit number (btst/bclr/bset/... @#k): the '@#' prefix.
				rz_strbuf_appendf(&sb, "@#0x%" PFMT64x, op->imm);
			} else if (op->neg_imm) {
				// A negated-magnitude immediate (mov -#k, dst): the minus sign
				// precedes the prefix (C55x+ "-#0x1", C55x "-0x1"), always printed
				// even for -0.
				ut64 mag = (ut64)(-(st64)op->imm);
				if (c55x) {
					rz_strbuf_appendf(&sb, "-0x%" PFMT64X, mag);
				} else {
					rz_strbuf_appendf(&sb, "-#0x%" PFMT64x, mag);
				}
			} else if (op->hash_dec) {
				// A fixed literal shift count rendered as a signed decimal
				// with the '#' prefix (the sftl dst, #1 / #-1 forms).
				rz_strbuf_appendf(&sb, "#%" PFMT64d, (st64)op->imm);
			} else if (op->addr) {
				if (a->arch == C55_ARCH_C54X) {
					// C54x renders program/data addresses as a bare hex value
					// (the '#' prefix is reserved for immediates).
					rz_strbuf_appendf(&sb, "0x%" PFMT64x, op->imm);
				} else {
					rz_strbuf_appendf(&sb, c55x ? "%s0x%06" PFMT64X : "%s0x%06" PFMT64x, ip, op->imm);
				}
			} else if (op->imm_signed && (st64)op->imm < 0) {
				rz_strbuf_appendf(&sb, c55x ? "%s-0x%" PFMT64X : "%s-0x%" PFMT64x, ip, (ut64)(-(st64)op->imm));
			} else if (c55x) {
				// C55x immediates are printed zero-padded to their field
				// width (one hex digit per 4 bits): a k4 stays a single
				// digit, a k8 prints as two, etc.
				int digits = (op->width + 3) / 4;
				rz_strbuf_appendf(&sb, "%s0x%0*" PFMT64X, ip, digits < 1 ? 1 : digits, op->imm);
			} else {
				rz_strbuf_appendf(&sb, "%s0x%" PFMT64x, ip, op->imm);
			}
			if (op->sh_left && op->shamt_hex) {
				// A variable shift count rendered as hex; always emitted, even
				// when zero. C55x prints it without a '#' and in uppercase (the
				// opcode-0x70..0x75 forms); C55x+ uses the "#0x%x" algebraic
				// form (the opcode-0xc2 forms).
				if (a->arch == C55_ARCH_C55X) {
					rz_strbuf_appendf(&sb, " << 0x%X", (unsigned)(ut8)op->shamt);
				} else {
					rz_strbuf_appendf(&sb, " << #0x%x", (unsigned)(ut8)op->shamt);
				}
			} else if (op->sh_left && op->shamt) {
				// A fixed shift rendered as a decimal "#N" (the opcode-0x7a /
				// 0xc0 "#k16 << #16" immediate-ALU forms).
				rz_strbuf_appendf(&sb, " << #%d", op->shamt);
			}
			break;
		}
		case C55_OP_MEM:
			if (op->mem_round) {
				// rounding store/load: the whole memory operand (including
				// any "<< Tx" shift) is wrapped in rnd(...).
				rz_strbuf_append(&sb, "rnd(");
			}
			if (op->dbl) {
				rz_strbuf_append(&sb, "dbl(");
			}
			if (op->dual_wrap) {
				rz_strbuf_append(&sb, "dual(");
			}
			if (insn->uns_all && op->uns) {
				// the 'u' mnemonic suffix covers the unsignedness; render the
				// memory operand itself without its own uns() wrapper.
				C55Operand bare = *op;
				bare.uns = false;
				c55_fmt_mem(&sb, a, &bare);
			} else {
				c55_fmt_mem(&sb, a, op);
			}
			if (op->dbl) {
				rz_strbuf_append(&sb, ")");
			}
			if (op->dual_wrap) {
				rz_strbuf_append(&sb, ")");
			}
			if (op->sh_left && op->shamt_hex) {
				// A fixed shift rendered as "#0x%x", always emitted even when
				// zero (the opcode-0xb7 shifted-load forms).
				rz_strbuf_appendf(&sb, " << #0x%x", (unsigned)(ut8)op->shamt);
			} else if (op->sh_left && op->shamt) {
				rz_strbuf_appendf(&sb, " << #%d", op->shamt);
			}
			if (op->sh_mem_reg_set) {
				rz_strbuf_append(&sb, " << ");
				c55_fmt_reg(&sb, a, &op->sh_mem_reg);
			}
			if (op->mem_round) {
				rz_strbuf_append(&sb, ")");
			}
			break;
		case C55_OP_COND: {
			static const char *const rel[] = { "==", "!=", "<", "<=", ">", ">=" };
			// status-bit flag conditions (C55x condition field, ids 0..31)
			static const char *const cond_flags[32] = {
				"overflow(ac0)", "overflow(ac1)", "overflow(ac2)", "overflow(ac3)",
				"tc1", "tc2", "carry", "overflow(govf)",
				"tc1 & tc2", "tc1 & !tc2", "!tc1 & tc2", "!tc1 & !tc2",
				"word_mode", "byte_mode", NULL, NULL,
				"!overflow(ac0)", "!overflow(ac1)", "!overflow(ac2)", "!overflow(ac3)",
				"!tc1", "!tc2", "!carry", "!overflow(govf)",
				"tc1 | tc2", "tc1 | !tc2", "!tc1 | tc2", "!tc1 | !tc2",
				"tc1 ^ tc2", "tc1 ^ !tc2", "!tc1 ^ tc2", "!tc1 ^ !tc2"
			};
			if (op->cond_is_flag) {
				const char *f = (op->cond_flag < 32) ? cond_flags[op->cond_flag] : NULL;
				rz_strbuf_append(&sb, f ? f : "");
				break;
			}
			if (op->cmp_mem) {
				c55_fmt_mem(&sb, a, op);
			} else {
				c55_fmt_reg(&sb, a, &op->reg);
			}
			rz_strbuf_appendf(&sb, " %s ", rel[op->relop % 6]);
			if (op->cmp_to_reg) {
				c55_fmt_reg(&sb, a, &op->index);
			} else if (op->cmp_imm) {
				if (a->arch == C55_ARCH_C55X) {
					int digits = (op->width + 3) / 4;
					rz_strbuf_appendf(&sb, "0x%0*" PFMT64X, digits < 1 ? 1 : digits, op->imm);
				} else {
					rz_strbuf_appendf(&sb, "#0x%" PFMT64x, op->imm);
				}
			} else {
				// C55x renders the zero comparison as a bare 0; C55x+ keeps the
				// '#' immediate prefix.
				rz_strbuf_append(&sb, a->arch == C55_ARCH_C55X ? "0" : "#0");
			}
			break;
		}
		default: break;
		}
		if (i == 2 && insn->shift16) {
			// macm ... ACx >> #16[, ACy]: the accumulator term (always the
			// third operand -- the source AC, or the destination in the
			// two-operand form) is rendered with a ">> #16" suffix.
			rz_strbuf_append(&sb, " >> #16");
		}
	}
	return rz_strbuf_drain_nofree(&sb);
}

#include <rz_il/rz_il_opbuilder_end.h>
