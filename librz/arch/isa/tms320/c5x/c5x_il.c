// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * TMS320C5x mnemonic, op-type and RzIL lifter.
 *
 * Shared-semantics instructions carry the C2X_INS_* ids and are handled by the
 * C2x consumers; this file only adds the C5x-only ids (the C5X_INS_* enum) and
 * the few shared ids whose C5x mnemonic differs from the C2x spelling (the
 * immediate forms add/sub/lar/rpt/ldp). The lifter reuses the C2x lifter for
 * the shared ids and for C5x-only ops that are semantically a renamed C2x op
 * (LACC == LAC, the delayed branches == their non-delayed forms); the remaining
 * C5x-only core ops (ACCB loads/logical, ZAP/ZPR, SETC/CLRC, SPLK) are lifted
 * here. C5x-only ops with effects the per-instruction RzIL cannot model cleanly
 * (conditional control transfers, block moves, parallel-logic, memory-mapped
 * register access, the MAC fetch forms) are decoded and analysed but left
 * without IL, exactly as the C2x leaves RPT/RPTK.
 */

#include "c5x.h"
#include <rz_il/rz_il_opbuilder_begin.h>

// A single 0/1 flag write helper for SETC/CLRC.
static RzILOpEffect *c5x_set_flag(const char *name, bool set) {
	return SETG(name, set ? IL_TRUE : IL_FALSE);
}

// AR[ARP] resolved at run time (mirrors the C2x model), for the page-0 / direct
// access of the simple C5x-only ops lifted here.
static const char *const c5x_ar[8] = {
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7"
};
static RzILOpPure *c5x_ind_addr(void) {
	RzILOpPure *v = VARG("ar7");
	for (int k = 6; k >= 0; k--) {
		v = ITE(EQ(VARG("arp"), UN(16, (ut32)k)), VARG(c5x_ar[k]), v);
	}
	return v;
}
static RzILOpPure *c5x_addr(const C55Operand *m) {
	if (m->amode == C55_AM_DIRECT) {
		RzILOpPure *page = SHIFTL0(LOGAND(VARG("dp"), UN(16, 0x1ff)), UN(16, 7));
		return LOGOR(page, UN(16, (ut32)m->disp & 0x7f));
	}
	return c5x_ind_addr();
}
// Scale a word address to the byte-addressed IL VM space (see the C2x notes on
// C2X_WORD_BYTES / C2X_MEM_ADDR_BITS; the C5x shares that memory model).
static RzILOpPure *c5x_byte(RzILOpPure *word_addr) {
	return MUL(UNSIGNED(C2X_MEM_ADDR_BITS, word_addr), UN(C2X_MEM_ADDR_BITS, C2X_WORD_BYTES));
}
// Callers must restrict these to direct operands: the indirect forms also
// post-modify the auxiliary register and can reload ARP, which is not modelled
// here, so lifting them would leave the AR file wrong.
static RzILOpPure *c5x_mem_read(const C55Operand *m) {
	return LOADW(16, c5x_byte(c5x_addr(m)));
}
static RzILOpEffect *c5x_mem_write(const C55Operand *m, RzILOpPure *val) {
	return STOREW(c5x_byte(c5x_addr(m)), val);
}

/**
 * \brief Lift one decoded C5x instruction to RzIL.
 * \param insn Decoded instruction
 * \param pc Address of \p insn, for PC-relative effects
 * \return Newly allocated effect, or NULL if \p insn has no lifter yet
 *
 * C5x-only ops are lifted here; the shared ids delegate to \ref c2x_lift.
 */
RZ_IPI RzILOpEffect *c5x_lift(const C55Insn *insn, ut64 pc) {
	// Shared-semantics ops, and C5x-only ops that are a renamed C2x op, are
	// lifted by the C2x lifter after mapping the id to its C2x equivalent.
	ut16 cid = 0;
	switch (insn->id) {
	case C5X_INS_LACC: cid = C2X_INS_LAC; break;
	case C5X_INS_BD: cid = C2X_INS_B; break;
	case C5X_INS_CALLD: cid = C2X_INS_CALL; break;
	case C5X_INS_BANZD: cid = C2X_INS_BANZ; break;
	case C5X_INS_BACCD: cid = C2X_INS_BACC; break;
	case C5X_INS_CALAD: cid = C2X_INS_CALA; break;
	case C5X_INS_RETE:
	case C5X_INS_RETI:
	case C5X_INS_RETD: cid = C2X_INS_RET; break;
	default: break;
	}
	if (cid) {
		C55Insn tmp = *insn;
		tmp.id = cid;
		return c2x_lift(&tmp, pc);
	}

	switch (insn->id) {
	case C5X_INS_LACL:
		// load ACC with a zero-extended 16-bit memory word or 8-bit immediate
		if (insn->ops[0].kind == C55_OP_IMM) {
			return SETG("acc", UN(32, (ut32)insn->ops[0].imm & 0xff));
		}
		if (insn->ops[0].amode != C55_AM_DIRECT) {
			return NULL;
		}
		return SETG("acc", UNSIGNED(32, c5x_mem_read(&insn->ops[0])));
	case C5X_INS_LACB:
		return SETG("acc", VARG("accb"));
	case C5X_INS_SACB:
		return SETG("accb", VARG("acc"));
	case C5X_INS_EXAR:
		return SEQ3(SETL("t", VARG("acc")), SETG("acc", VARG("accb")),
			SETG("accb", VARL("t")));
	case C5X_INS_ANDB:
		return SETG("acc", LOGAND(VARG("acc"), VARG("accb")));
	case C5X_INS_ORB:
		return SETG("acc", LOGOR(VARG("acc"), VARG("accb")));
	case C5X_INS_XORB:
		return SETG("acc", LOGXOR(VARG("acc"), VARG("accb")));
	case C5X_INS_ZAP:
		return SEQ2(SETG("acc", UN(32, 0)), SETG("p", UN(32, 0)));
	case C5X_INS_ZPR:
		return SETG("p", UN(32, 0));
	case C5X_INS_SPLK:
		// store a long immediate constant to the memory operand
		if (insn->ops[0].amode != C55_AM_DIRECT) {
			return NULL;
		}
		return c5x_mem_write(&insn->ops[0], UN(16, (ut32)insn->ops[insn->n_ops - 1].imm & 0xffff));
	case C5X_INS_SETC:
	case C5X_INS_CLRC: {
		// only the control bits with a dedicated IL flag are modelled
		const char *r = insn->ops[0].raw;
		bool set = (insn->id == C5X_INS_SETC);
		if (!r) {
			return NULL;
		}
		if (!strcmp(r, "ovm")) {
			return c5x_set_flag("ovm", set);
		}
		if (!strcmp(r, "sxm")) {
			return c5x_set_flag("sxm", set);
		}
		if (!strcmp(r, "carry")) {
			return c5x_set_flag("c", set);
		}
		if (!strcmp(r, "tc")) {
			return c5x_set_flag("tc", set);
		}
		return NULL; // intm/cnf/xf/hold: no dedicated IL state
	}
	default:
		break;
	}

	// Shared ids -> the C2x lifter. C5x-only ops not handled above are decoded
	// and analysed but intentionally left without IL.
	if (insn->id < C5X_INS_BASE) {
		return c2x_lift(insn, pc);
	}
	return NULL;
}
