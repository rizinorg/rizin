// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c6x_il_window.c
 * Lifting C6000 code over the cycles its effects take to land.
 *
 * Every instruction of an execute packet reads the register file as it stood
 * when the packet issued, and most write it at the end of that cycle; others
 * land later, a load four cycles on and a double-precision multiply nine
 * (SPRUFE8B 3.4). A branch takes effect five cycles after it issues, and the
 * packets issued in between still run. So the IL at an address covers more
 * than the execute packet there: the cycles until every effect it starts has
 * landed, or at least until nothing reads a register that is still in flight.
 *
 * The packets are issued cycle by cycle, a multi-cycle NOP counting all its
 * cycles. Each instruction runs at issue against the state of its cycle, and
 * what it writes is kept in locals until the cycle it lands in, unless nothing
 * could tell the difference. A branch's taken flag and target are kept the
 * same way, and the transfer happens at its cycle; a branch issued in the
 * delay slots of another one is followed into the first one's target, where
 * the second takes over. Results still in flight when control leaves are
 * written at the transfer, since the code at a target is not in hand.
 */

#include <rz_util.h>
#include "c6x.h"

#include <rz_il/rz_il_opbuilder_begin.h>

/** Packets one lift may issue, over all its paths. */
#define C6X_WIN_PACKETS 64
/** Results in flight at once. */
#define C6X_WIN_LANDINGS 48
/** Branches in flight at once. */
#define C6X_WIN_BRANCHES 8
/** Writes of one instruction. */
#define C6X_WIN_WRITES 8
/** Cycles from a branch issuing to its target issuing: the five delay slots and one. */
#define C6X_BRANCH_CYCLES 6
/** How many packets ahead a hazard is looked for, enough for the longest delay. */
#define C6X_WIN_LOOKAHEAD 16

// RzIL keeps a variable name as a const char * and never copies it, so the
// names a lift hands out are string literals: values in flight, whether they
// were written at all, snapshots of a packet's starting state, and a branch's
// taken flag and target.
// clang-format off
#define C6X_N10(p, t) p t "0", p t "1", p t "2", p t "3", p t "4", p t "5", p t "6", p t "7", p t "8", p t "9"
static const char *const c6x_val_names[] = {
	C6X_N10("_wv", ""), C6X_N10("_wv", "1"), C6X_N10("_wv", "2"), C6X_N10("_wv", "3"), C6X_N10("_wv", "4"),
	C6X_N10("_wv", "5"), C6X_N10("_wv", "6"), C6X_N10("_wv", "7"), C6X_N10("_wv", "8"), C6X_N10("_wv", "9")
};
static const char *const c6x_flag_names[] = {
	C6X_N10("_wf", ""), C6X_N10("_wf", "1"), C6X_N10("_wf", "2"), C6X_N10("_wf", "3"), C6X_N10("_wf", "4")
};
static const char *const c6x_snap_names[] = {
	C6X_N10("_ws", ""), C6X_N10("_ws", "1"), C6X_N10("_ws", "2")
};
static const char *const c6x_taken_names[] = {
	C6X_N10("_bt", ""), C6X_N10("_bt", "1"), C6X_N10("_bt", "2")
};
static const char *const c6x_target_names[] = {
	C6X_N10("_bg", ""), C6X_N10("_bg", "1"), C6X_N10("_bg", "2")
};
#undef C6X_N10
// clang-format on

/** A result in flight. */
typedef struct {
	const char *reg; ///< the register it lands in
	const char *val; ///< the local holding it
	const char *flag; ///< the local saying whether it was written, NULL when it always is
	ut32 due; ///< the cycle at whose end it lands
} C6xLanding;

/** A branch in flight. */
typedef struct {
	ut32 issued; ///< the cycle it issued in
	const char *taken; ///< the local saying whether it is taken, NULL when it always is
	const char *target; ///< the local holding the target, NULL when that is constant
	ut64 target_const; ///< the target, unless held in \c target
	ut8 creg; ///< the predicate of a branch taken on it alone, 0 for any other
	bool z; ///< its sense
	ut32 pred_written; ///< one past the cycle of the last write to it the branch saw
} C6xFlight;

/** Where one path through the lift stands. */
typedef struct {
	ut64 pc; ///< the next packet to issue
	ut32 cycle; ///< the cycle it issues in
	C6xLanding land[C6X_WIN_LANDINGS];
	size_t nland;
	C6xFlight br[C6X_WIN_BRANCHES];
	size_t nbr;
	size_t nval, nflag, ntaken, ntarget; ///< locals handed out on this path
	ut32 pred_written[8]; ///< by creg: one past the cycle of the last write to the register
} C6xWinState;

typedef struct {
	C6xPacketFn packet; ///< decodes the execute packet at an address
	void *user;
	ut64 fall; ///< where the caller falls through to, or C6X_FALL_TO_END
	size_t budget; ///< packets left to issue
	ut64 end; ///< where the fallthrough path leaves the code covered
	bool has_end;
} C6xWin;

/** A register an instruction writes. */
typedef struct {
	const char *reg;
	bool cond; ///< written only on some paths through the instruction
	ut8 delay; ///< delay slots before it lands
	bool staged; ///< kept in flight rather than written in place
	const char *val; ///< the local holding it, when staged
	const char *flag; ///< the local saying whether it was written, when staged and cond
} C6xWrite;

/** An instruction of the packet being issued. */
typedef struct {
	const C6xInsn *insn;
	RzILOpEffect *body;
	C6xWrite w[C6X_WIN_WRITES];
	size_t nw;
	bool at_once; ///< what it writes lands with the cycle, whatever the delay slots of \ref insn
	bool jumps; ///< it is a branch
	bool jump_cond; ///< taken on some paths only
	bool target_is_const;
	ut64 target_const;
	const char *taken;
	const char *target;
} C6xIssue;

static const char *c6x_take_name(const char *const *tbl, size_t len, size_t *next) {
	return *next < len ? tbl[(*next)++] : NULL;
}

// Whether \p insn names \p reg in an operand, tests it as its predicate or
// reaches it implicitly. Over-approximating is safe: it only keeps a result in
// flight where it could have been written at once.
static bool c6x_touches(const C6xInsn *insn, const char *reg) {
	const char *pred = insn->creg ? c6x_pred_reg_name(insn->creg) : NULL;
	if (pred && RZ_STR_EQ(pred, reg)) {
		return true;
	}
	for (ut8 i = 0; i < insn->nops; i++) {
		const C6xOperand *o = &insn->ops[i];
		ut8 count = 0;
		switch (o->kind) {
		case C6X_OP_REG: count = 1; break;
		case C6X_OP_REGPAIR: count = 2; break;
		case C6X_OP_REGQUAD: count = 4; break;
		case C6X_OP_MEM:
			if (RZ_STR_EQ(c6x_il_reg(o->v.mem.base_side, o->v.mem.base), reg) ||
				RZ_STR_EQ(c6x_il_reg(o->v.mem.base_side, o->v.mem.off_reg), reg)) {
				return true;
			}
			break;
		case C6X_OP_CTRLREG:
			if (o->v.ctrl && RZ_STR_EQ(o->v.ctrl, reg)) {
				return true;
			}
			break;
		default:
			break;
		}
		for (ut8 k = 0; k < count; k++) {
			if (RZ_STR_EQ(c6x_il_reg(o->v.reg.side, o->v.reg.num + k), reg)) {
				return true;
			}
		}
	}
	switch (insn->id) {
	case C6X_INS_DINT:
	case C6X_INS_RINT:
		return RZ_STR_EQ(reg, "csr") || RZ_STR_EQ(reg, "tsr");
	default:
		return false;
	}
}

// The creg code testing \p reg, 0 when it is no predicate register.
static ut8 c6x_creg_of(const char *reg) {
	for (ut8 c = 1; c < 7; c++) {
		if (RZ_STR_EQ(c6x_pred_reg_name(c), reg)) {
			return c;
		}
	}
	return 0;
}

// Note that \p reg was written in \p cycle, for telling whether two branches
// tested the same value of their predicate.
static void c6x_note_write(C6xWinState *st, const char *reg, ut32 cycle) {
	ut8 c = c6x_creg_of(reg);
	if (c && st->pred_written[c] < cycle + 1) {
		st->pred_written[c] = cycle + 1;
	}
}

// Whether \p b and \p o are taken on one value of one predicate register: it
// was not written between their tests.
static bool c6x_same_test(const C6xFlight *b, const C6xFlight *o) {
	const C6xFlight *early = b->issued <= o->issued ? b : o;
	const C6xFlight *late = early == b ? o : b;
	return b->creg && b->creg == o->creg && late->pred_written <= early->issued;
}

// Settle the branches in flight that the outcome of \p b decides: those on the
// same test are taken when it is, those on the opposite one when it is not,
// and the others are dropped. Left undecided, a path the IL cannot take would
// still be lifted, and analysis would find edges that are not there.
static void c6x_settle(C6xWinState *st, const C6xFlight *b, bool taken) {
	size_t keep = 0;
	for (size_t i = 0; i < st->nbr; i++) {
		C6xFlight o = st->br[i];
		if (c6x_same_test(b, &o)) {
			if ((b->z != o.z) == taken) {
				continue;
			}
			o.taken = NULL;
		}
		st->br[keep++] = o;
	}
	st->nbr = keep;
}

// Whether a slot writes memory, i.e. is a store.
static bool c6x_writes_memory(const C6xInsn *insn) {
	return insn->nops && insn->ops[insn->nops - 1].kind == C6X_OP_MEM;
}

// The cycles an execute packet takes: one, or as many as its multi-cycle NOP.
static ut32 c6x_packet_cycles(const C6xInsn *slots, size_t first, size_t n) {
	ut8 extra = 0;
	for (size_t i = first; i < n; i++) {
		extra = RZ_MAX(extra, c6x_nop_cycles(&slots[i]));
	}
	return 1 + extra;
}

// The delay slots of a write of \p reg by \p insn: those of its result when
// \p reg is the destination, none for an address update or the like.
static ut8 c6x_write_delay(const C6xInsn *insn, const char *reg) {
	if (!insn->nops) {
		return 0;
	}
	const C6xOperand *d = &insn->ops[insn->nops - 1];
	ut8 n;
	switch (d->kind) {
	case C6X_OP_REG: n = 1; break;
	case C6X_OP_REGPAIR: n = 2; break;
	case C6X_OP_REGQUAD: n = 4; break;
	default: return 0;
	}
	for (ut8 i = 0; i < n; i++) {
		if (RZ_STR_EQ(c6x_il_reg(d->v.reg.side, d->v.reg.num + i), reg)) {
			// the odd register of a pair may land a cycle late, a quad lands at once
			return c6x_delay_slots(insn, d->kind == C6X_OP_REGPAIR && i);
		}
	}
	return 0;
}

// Collect the registers \p e writes, noting those written on some paths only.
static bool c6x_collect_writes(const RzILOpEffect *e, bool cond, C6xIssue *is) {
	if (!e) {
		return true;
	}
	switch (e->code) {
	case RZ_IL_OP_SET: {
		if (e->op.set.is_local) {
			return true;
		}
		for (size_t i = 0; i < is->nw; i++) {
			if (RZ_STR_EQ(is->w[i].reg, e->op.set.v)) {
				is->w[i].cond &= cond;
				return true;
			}
		}
		if (is->nw >= C6X_WIN_WRITES) {
			return false;
		}
		C6xWrite *w = &is->w[is->nw++];
		memset(w, 0, sizeof(*w));
		w->reg = e->op.set.v;
		w->cond = cond;
		w->delay = is->at_once ? 0 : c6x_write_delay(is->insn, w->reg);
		return true;
	}
	case RZ_IL_OP_SEQ:
		return c6x_collect_writes(e->op.seq.x, cond, is) && c6x_collect_writes(e->op.seq.y, cond, is);
	case RZ_IL_OP_BRANCH:
		return c6x_collect_writes(e->op.branch.true_eff, true, is) && c6x_collect_writes(e->op.branch.false_eff, true, is);
	case RZ_IL_OP_REPEAT:
		return c6x_collect_writes(e->op.repeat.data_eff, true, is);
	case RZ_IL_OP_BLK:
		return c6x_collect_writes(e->op.blk.data_eff, cond, is) && c6x_collect_writes(e->op.blk.ctrl_eff, cond, is);
	default:
		return true;
	}
}

// Set \p flag after every write of \p reg in \p e, so a later write-back knows
// whether the instruction wrote it.
static RzILOpEffect *c6x_flag_writes(RzILOpEffect *e, const char *reg, const char *flag) {
	if (!e) {
		return NULL;
	}
	switch (e->code) {
	case RZ_IL_OP_SET:
		if (!e->op.set.is_local && RZ_STR_EQ(e->op.set.v, reg)) {
			return SEQ2(e, SETL(flag, IL_TRUE));
		}
		return e;
	case RZ_IL_OP_SEQ:
		e->op.seq.x = c6x_flag_writes(e->op.seq.x, reg, flag);
		e->op.seq.y = c6x_flag_writes(e->op.seq.y, reg, flag);
		return e;
	case RZ_IL_OP_BRANCH:
		e->op.branch.true_eff = c6x_flag_writes(e->op.branch.true_eff, reg, flag);
		e->op.branch.false_eff = c6x_flag_writes(e->op.branch.false_eff, reg, flag);
		return e;
	case RZ_IL_OP_REPEAT:
		e->op.repeat.data_eff = c6x_flag_writes(e->op.repeat.data_eff, reg, flag);
		return e;
	default:
		return e;
	}
}

// Replace the jump in \p e by setting the branch's taken flag and target, so the
// instruction can run at issue and the transfer happen cycles later. NULL when
// \p e jumps in more than one place.
static RzILOpEffect *c6x_capture_jump(RzILOpEffect *e, bool cond, C6xIssue *is, bool *ok) {
	if (!e || !*ok) {
		return e;
	}
	switch (e->code) {
	case RZ_IL_OP_JMP: {
		if (is->jumps) {
			*ok = false;
			return e;
		}
		is->jumps = true;
		is->jump_cond = cond;
		RzILOpPure *dst = e->op.jmp.dst;
		e->op.jmp.dst = NULL;
		rz_il_op_effect_free(e);
		RzILOpEffect *tgt = NULL;
		if (dst->code == RZ_IL_OP_BITV) {
			is->target_is_const = true;
			is->target_const = rz_bv_to_ut64(dst->op.bitv.value);
			rz_il_op_pure_free(dst);
		} else {
			tgt = SETL(is->target, dst);
		}
		RzILOpEffect *tk = cond ? SETL(is->taken, IL_TRUE) : NULL;
		if (tgt && tk) {
			return SEQ2(tgt, tk);
		}
		return tgt ? tgt : tk ? tk
				      : NOP();
	}
	case RZ_IL_OP_SEQ: {
		e->op.seq.x = c6x_capture_jump(e->op.seq.x, cond, is, ok);
		e->op.seq.y = c6x_capture_jump(e->op.seq.y, cond, is, ok);
		// a jump replaced by nothing leaves a NOP not worth keeping
		RzILOpEffect *keep = NULL;
		if (e->op.seq.y && e->op.seq.y->code == RZ_IL_OP_NOP) {
			keep = e->op.seq.x;
			e->op.seq.x = NULL;
		} else if (e->op.seq.x && e->op.seq.x->code == RZ_IL_OP_NOP) {
			keep = e->op.seq.y;
			e->op.seq.y = NULL;
		}
		if (keep) {
			rz_il_op_effect_free(e);
			return keep;
		}
		return e;
	}
	case RZ_IL_OP_BRANCH:
		e->op.branch.true_eff = c6x_capture_jump(e->op.branch.true_eff, true, is, ok);
		e->op.branch.false_eff = c6x_capture_jump(e->op.branch.false_eff, true, is, ok);
		return e;
	case RZ_IL_OP_GOTO:
		*ok = false;
		return e;
	default:
		return e;
	}
}

// Whether \p e transfers control.
static bool c6x_effect_jumps(const RzILOpEffect *e) {
	if (!e) {
		return false;
	}
	switch (e->code) {
	case RZ_IL_OP_JMP:
	case RZ_IL_OP_GOTO:
		return true;
	case RZ_IL_OP_SEQ:
		return c6x_effect_jumps(e->op.seq.x) || c6x_effect_jumps(e->op.seq.y);
	case RZ_IL_OP_BRANCH:
		return c6x_effect_jumps(e->op.branch.true_eff) || c6x_effect_jumps(e->op.branch.false_eff);
	case RZ_IL_OP_BLK:
		return c6x_effect_jumps(e->op.blk.ctrl_eff);
	default:
		return false;
	}
}

// Whether a packet issuing within the cycles from \p cycle to \p due touches
// \p reg, following the fallthrough path from \p pc.
static bool c6x_touched_ahead(C6xWin *win, ut64 pc, ut32 cycle, const char *reg, ut32 due) {
	for (size_t k = 0; k < C6X_WIN_LOOKAHEAD && cycle <= due; k++) {
		C6xInsn ins[C6X_FP_SLOTS];
		C6xPacketRef p;
		size_t n = win->packet(win->user, pc, ins, &p);
		if (!n) {
			return false;
		}
		for (size_t i = 0; i < n; i++) {
			if (c6x_touches(&ins[i], reg)) {
				return true;
			}
		}
		cycle += c6x_packet_cycles(ins, 0, n);
		pc = p.next;
	}
	return false;
}

// Whether a result in flight is touched before it lands.
static bool c6x_hazard_ahead(C6xWin *win, const C6xWinState *st) {
	for (size_t i = 0; i < st->nland; i++) {
		const C6xLanding *l = &st->land[i];
		if (l->due >= st->cycle && c6x_touched_ahead(win, st->pc, st->cycle, l->reg, l->due)) {
			return true;
		}
	}
	return false;
}

static RzILOpEffect *c6x_landing_write(const C6xLanding *l) {
	RzILOpEffect *wr = SETG(l->reg, VARL(l->val));
	return l->flag ? BRANCH(VARL(l->flag), wr, NOP()) : wr;
}

// Write the results due before \p cycle, in the order they land, and drop them
// from the state.
static void c6x_land_before(C6xWinState *st, ut32 cycle, RzPVector /*<RzILOpEffect *>*/ *steps) {
	for (;;) {
		size_t best = SIZE_MAX;
		for (size_t i = 0; i < st->nland; i++) {
			if (st->land[i].due < cycle && (best == SIZE_MAX || st->land[i].due < st->land[best].due)) {
				best = i;
			}
		}
		if (best == SIZE_MAX) {
			return;
		}
		rz_pvector_push(steps, c6x_landing_write(&st->land[best]));
		c6x_note_write(st, st->land[best].reg, st->land[best].due);
		memmove(&st->land[best], &st->land[best + 1], (st->nland - best - 1) * sizeof(C6xLanding));
		st->nland--;
	}
}

// Every result in flight, in the order they land, leaving the state as it is.
static void c6x_land_copy(const C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps) {
	C6xWinState tmp;
	tmp.nland = st->nland;
	memcpy(tmp.land, st->land, st->nland * sizeof(C6xLanding));
	c6x_land_before(&tmp, UT32_MAX, steps);
}

// Fold \p n effects into a balanced sequence, so the depth grows with the
// logarithm of a long window rather than its length.
static RzILOpEffect *c6x_fold(RzILOpEffect **v, size_t n) {
	if (n == 1) {
		return v[0];
	}
	size_t h = n / 2;
	return SEQ2(c6x_fold(v, h), c6x_fold(v + h, n - h));
}

// The steps followed by \p tail, which ends the effect.
static RzILOpEffect *c6x_seal(RzPVector /*<RzILOpEffect *>*/ *steps, RzILOpEffect *tail) {
	if (tail) {
		rz_pvector_push(steps, tail);
	}
	size_t n = rz_pvector_len(steps);
	RzILOpEffect *r = n ? c6x_fold((RzILOpEffect **)rz_pvector_data(steps), n) : NOP();
	rz_pvector_clear(steps);
	return r;
}

static void c6x_steps_free(RzPVector /*<RzILOpEffect *>*/ *steps) {
	void **it;
	rz_pvector_foreach (steps, it) {
		rz_il_op_effect_free(*it);
	}
	rz_pvector_clear(steps);
}

// The body of a slot: what it does when it issues.
static RzILOpEffect *c6x_slot_body(const C6xInsn *insn, ut64 addr, const C6xPacketRef *pkt) {
	if (insn->id == C6X_INS_CALLP) {
		// it returns to the execute packet after its own
		return c6x_lift_call(insn, addr, pkt->next);
	}
	return c6x_lift(insn, addr);
}

static void c6x_issues_fini(C6xIssue *is, size_t n) {
	for (size_t i = 0; i < n; i++) {
		rz_il_op_effect_free(is[i].body);
		is[i].body = NULL;
	}
}

// Issue the execute packet at st->pc from the slot there on, in cycle
// st->cycle: every slot reads the state the packet found, and what lands later
// or is read again within the packet goes into flight.
static bool c6x_win_issue(C6xWin *win, C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps) {
	if (!win->budget) {
		RZ_LOG_DEBUG("c6x: lifting at 0x%" PFMT64x " issues more packets than one lift may\n", st->pc);
		return false;
	}
	win->budget--;
	C6xInsn slots[C6X_FP_SLOTS];
	C6xPacketRef pkt;
	size_t n = win->packet(win->user, st->pc, slots, &pkt);
	if (!n || (pkt.n == 1 && pkt.slots[0].header)) {
		RZ_LOG_DEBUG("c6x: no execute packet to lift at 0x%" PFMT64x "\n", st->pc);
		return false;
	}
	size_t first = 0;
	while (first < n && pkt.slots[first].addr != st->pc) {
		first++;
	}
	if (first == n) {
		return false;
	}
	ut32 cycle = st->cycle;
	ut32 next_cycle = cycle + c6x_packet_cycles(slots, first, n);
	// A load and a store to the same location in one packet load the old value
	// (SPRUFE8B 4.2), so the slots reading memory run first. A load into the
	// register its address mode updates writes it twice, so it issues as two:
	// the address lands with the cycle, what it loads after the delay slots.
	size_t order[2 * C6X_FP_SLOTS];
	size_t nord = 0;
	for (size_t i = first; i < n; i++) {
		if (!c6x_writes_memory(&slots[i])) {
			order[nord++] = i;
			if (c6x_load_into_base(&slots[i])) {
				order[nord++] = i;
			}
		}
	}
	for (size_t i = first; i < n; i++) {
		if (c6x_writes_memory(&slots[i])) {
			order[nord++] = i;
		}
	}
	C6xIssue is[2 * C6X_FP_SLOTS];
	memset(is, 0, sizeof(is));
	size_t jumps = 0;
	for (size_t o = 0; o < nord; o++) {
		size_t i = order[o];
		C6xIssue *x = &is[o];
		x->insn = &slots[i];
		bool twice = c6x_load_into_base(&slots[i]);
		x->at_once = twice && !(o && order[o - 1] == i);
		x->body = twice ? c6x_lift_load_part(&slots[i], pkt.slots[i].addr, x->at_once) : c6x_slot_body(&slots[i], pkt.slots[i].addr, &pkt);
		if (!x->body) {
			RZ_LOG_DEBUG("c6x: no IL for %s at 0x%" PFMT64x "\n", rz_str_get_null(c6x_ins_name(slots[i].id)), pkt.slots[i].addr);
			goto fail;
		}
		if (c6x_effect_jumps(x->body)) {
			x->taken = c6x_take_name(c6x_taken_names, RZ_ARRAY_SIZE(c6x_taken_names), &st->ntaken);
			x->target = c6x_take_name(c6x_target_names, RZ_ARRAY_SIZE(c6x_target_names), &st->ntarget);
			bool ok = x->taken && x->target;
			x->body = c6x_capture_jump(x->body, false, x, &ok);
			if (!ok || st->nbr + jumps >= C6X_WIN_BRANCHES) {
				RZ_LOG_DEBUG("c6x: too many branches in flight at 0x%" PFMT64x "\n", pkt.slots[i].addr);
				goto fail;
			}
			jumps++;
		}
		if (!c6x_collect_writes(x->body, false, x)) {
			goto fail;
		}
	}
	// A write is staged -- kept in a local until it lands -- when anything could
	// see it early: a later slot of the packet touching the register, a packet
	// before it lands doing so, or an earlier result still in flight to it.
	for (size_t o = 0; o < nord; o++) {
		for (size_t k = 0; k < is[o].nw; k++) {
			C6xWrite *w = &is[o].w[k];
			bool stage = false;
			for (size_t p = o + 1; p < nord && !stage; p++) {
				stage = c6x_touches(is[p].insn, w->reg);
			}
			for (size_t l = 0; l < st->nland && !stage; l++) {
				stage = RZ_STR_EQ(st->land[l].reg, w->reg);
			}
			if (!stage && w->delay) {
				stage = c6x_touched_ahead(win, pkt.next, next_cycle, w->reg, cycle + w->delay);
			}
			w->staged = stage;
		}
	}
	// every writer of a staged register is staged, so that they land in order
	for (size_t o = 0; o < nord; o++) {
		for (size_t k = 0; k < is[o].nw; k++) {
			for (size_t p = 0; p < nord; p++) {
				for (size_t q = 0; q < is[p].nw; q++) {
					if (is[p].w[q].staged && RZ_STR_EQ(is[p].w[q].reg, is[o].w[k].reg)) {
						is[o].w[k].staged = true;
					}
				}
			}
		}
	}
	// snapshots of the staged registers, which each slot is run against
	const char *staged[C6X_FP_SLOTS * C6X_WIN_WRITES];
	const char *snap[C6X_FP_SLOTS * C6X_WIN_WRITES];
	bool dirty[C6X_FP_SLOTS * C6X_WIN_WRITES] = { 0 };
	size_t nstaged = 0;
	for (size_t o = 0; o < nord; o++) {
		for (size_t k = 0; k < is[o].nw; k++) {
			C6xWrite *w = &is[o].w[k];
			if (!w->staged) {
				continue;
			}
			w->val = c6x_take_name(c6x_val_names, RZ_ARRAY_SIZE(c6x_val_names), &st->nval);
			w->flag = w->cond ? c6x_take_name(c6x_flag_names, RZ_ARRAY_SIZE(c6x_flag_names), &st->nflag) : NULL;
			if (!w->val || (w->cond && !w->flag)) {
				RZ_LOG_DEBUG("c6x: too many results in flight at 0x%" PFMT64x "\n", st->pc);
				goto fail;
			}
			size_t j = 0;
			while (j < nstaged && !RZ_STR_EQ(staged[j], w->reg)) {
				j++;
			}
			if (j == nstaged) {
				if (nstaged >= RZ_ARRAY_SIZE(c6x_snap_names)) {
					RZ_LOG_DEBUG("c6x: too many results in flight at 0x%" PFMT64x "\n", st->pc);
					goto fail;
				}
				staged[nstaged] = w->reg;
				snap[nstaged] = c6x_snap_names[nstaged];
				nstaged++;
			}
		}
	}
	for (size_t j = 0; j < nstaged; j++) {
		rz_pvector_push(steps, SETL(snap[j], VARG(staged[j])));
	}
	for (size_t o = 0; o < nord; o++) {
		C6xIssue *x = &is[o];
		// run against the state the packet found
		for (size_t j = 0; j < nstaged; j++) {
			if (dirty[j] && c6x_touches(x->insn, staged[j])) {
				rz_pvector_push(steps, SETG(staged[j], VARL(snap[j])));
				dirty[j] = false;
			}
		}
		if (x->jumps && x->jump_cond) {
			rz_pvector_push(steps, SETL(x->taken, IL_FALSE));
		}
		if (x->jumps && !x->target_is_const) {
			rz_pvector_push(steps, SETL(x->target, U32(0)));
		}
		for (size_t k = 0; k < x->nw; k++) {
			C6xWrite *w = &x->w[k];
			if (w->staged && w->flag) {
				rz_pvector_push(steps, SETL(w->flag, IL_FALSE));
				x->body = c6x_flag_writes(x->body, w->reg, w->flag);
			}
		}
		if (x->body->code == RZ_IL_OP_NOP) {
			// a NOP, or a branch whose transfer comes later
			rz_il_op_effect_free(x->body);
		} else {
			rz_pvector_push(steps, x->body);
		}
		x->body = NULL;
		for (size_t k = 0; k < x->nw; k++) {
			C6xWrite *w = &x->w[k];
			if (!w->staged) {
				c6x_note_write(st, w->reg, cycle);
				continue;
			}
			rz_pvector_push(steps, SETL(w->val, VARG(w->reg)));
			for (size_t j = 0; j < nstaged; j++) {
				dirty[j] |= RZ_STR_EQ(staged[j], w->reg);
			}
			if (st->nland >= C6X_WIN_LANDINGS) {
				RZ_LOG_DEBUG("c6x: too many results in flight at 0x%" PFMT64x "\n", st->pc);
				goto fail;
			}
			C6xLanding *l = &st->land[st->nland++];
			l->reg = w->reg;
			l->val = w->val;
			l->flag = w->flag;
			l->due = cycle + w->delay;
		}
		if (x->jumps) {
			C6xFlight *b = &st->br[st->nbr++];
			b->issued = cycle;
			b->taken = x->jump_cond ? x->taken : NULL;
			b->target = x->target_is_const ? NULL : x->target;
			b->target_const = x->target_const;
			// only B and BNOP are taken on their predicate alone
			bool plain = x->insn->id == C6X_INS_B || x->insn->id == C6X_INS_BNOP;
			b->creg = plain && x->jump_cond ? x->insn->creg : 0;
			b->z = x->insn->z;
			b->pred_written = b->creg ? st->pred_written[b->creg & 7] : 0;
		}
	}
	// the packet's own writes land at the end of its cycle at the earliest
	for (size_t j = 0; j < nstaged; j++) {
		if (dirty[j]) {
			rz_pvector_push(steps, SETG(staged[j], VARL(snap[j])));
		}
	}
	st->pc = pkt.next;
	st->cycle = next_cycle;
	return true;
fail:
	c6x_issues_fini(is, nord);
	return false;
}

static RzILOpEffect *c6x_flight_jump(const C6xFlight *b) {
	return JMP(b->target ? VARL(b->target) : U32((ut32)b->target_const));
}

static RzILOpEffect *c6x_win_run(C6xWin *win, C6xWinState *st, bool main_path, bool issue_first);

// The transfer of branch \p b out of the steps so far: when taken, control
// leaves with every result in flight written, unless a later branch is still
// in flight, which is followed into the target until it takes over.
static RzILOpEffect *c6x_win_taken(C6xWin *win, const C6xWinState *st, const C6xFlight *b, ut32 at) {
	RzPVector steps;
	rz_pvector_init(&steps, NULL);
	c6x_land_copy(st, &steps);
	RzILOpEffect *leave = c6x_seal(&steps, c6x_flight_jump(b));
	rz_pvector_fini(&steps);
	if (!leave) {
		return NULL;
	}
	C6xWinState *fork = RZ_NEW(C6xWinState);
	if (!fork) {
		rz_il_op_effect_free(leave);
		return NULL;
	}
	*fork = *st;
	fork->pc = b->target_const;
	fork->cycle = at;
	c6x_settle(fork, b, true);
	// two branches taking effect in one cycle are undefined, so those landing
	// with this one are not taken
	size_t keep = 0;
	for (size_t i = 0; i < fork->nbr; i++) {
		if (fork->br[i].issued + C6X_BRANCH_CYCLES > at) {
			fork->br[keep++] = fork->br[i];
		}
	}
	fork->nbr = keep;
	RzILOpPure *later = NULL;
	bool surely = false;
	for (size_t i = 0; i < fork->nbr && !surely; i++) {
		const C6xFlight *o = &fork->br[i];
		if (!o->taken) {
			surely = true;
			rz_il_op_pure_free(later);
			later = NULL;
		} else {
			later = later ? OR(later, VARL(o->taken)) : VARL(o->taken);
		}
	}
	if (!later && !surely) {
		free(fork);
		return leave;
	}
	if (b->target) {
		// A computed target is not in hand to be followed, so the branches
		// still in flight are dropped, which is wrong when one of them is
		// taken too.
		RZ_LOG_DEBUG("c6x: a branch to a computed target drops the branches in flight\n");
		rz_il_op_pure_free(later);
		free(fork);
		return leave;
	}
	RzILOpEffect *follow = c6x_win_run(win, fork, false, true);
	free(fork);
	if (!follow || surely) {
		rz_il_op_pure_free(later);
		rz_il_op_effect_free(leave);
		return follow;
	}
	return BRANCH(later, follow, leave);
}

// Lift from \p st on: issue packets until no branch is in flight and nothing
// reads a result before it lands, then write what is in flight and leave.
static RzILOpEffect *c6x_win_run(C6xWin *win, C6xWinState *st, bool main_path, bool issue_first) {
	RzPVector steps;
	rz_pvector_init(&steps, NULL);
	RzILOpEffect *tail = NULL;
	if (issue_first && !c6x_win_issue(win, st, &steps)) {
		goto fail;
	}
	for (;;) {
		c6x_land_before(st, st->cycle, &steps);
		size_t bi = SIZE_MAX;
		for (size_t i = 0; i < st->nbr; i++) {
			if (bi == SIZE_MAX || st->br[i].issued < st->br[bi].issued) {
				bi = i;
			}
		}
		if (bi != SIZE_MAX && st->br[bi].issued + C6X_BRANCH_CYCLES <= st->cycle) {
			C6xFlight b = st->br[bi];
			memmove(&st->br[bi], &st->br[bi + 1], (st->nbr - bi - 1) * sizeof(C6xFlight));
			st->nbr--;
			ut32 at = b.issued + C6X_BRANCH_CYCLES;
			RzILOpEffect *taken = c6x_win_taken(win, st, &b, at);
			if (!taken) {
				goto fail;
			}
			if (!b.taken) {
				if (main_path && !win->has_end) {
					win->end = st->pc;
					win->has_end = true;
				}
				tail = taken;
				break;
			}
			c6x_settle(st, &b, false);
			RzILOpEffect *rest = c6x_win_run(win, st, main_path, false);
			if (!rest) {
				rz_il_op_effect_free(taken);
				goto fail;
			}
			tail = BRANCH(VARL(b.taken), taken, rest);
			break;
		}
		if (!st->nbr && !c6x_hazard_ahead(win, st)) {
			c6x_land_before(st, UT32_MAX, &steps);
			if (main_path) {
				win->end = st->pc;
				win->has_end = true;
			}
			if (!main_path || (win->fall != C6X_FALL_TO_END && win->fall != st->pc)) {
				tail = JMP(U32((ut32)st->pc));
			}
			break;
		}
		if (!c6x_win_issue(win, st, &steps)) {
			goto fail;
		}
	}
	RzILOpEffect *r = c6x_seal(&steps, tail);
	rz_pvector_fini(&steps);
	return r;
fail:
	c6x_steps_free(&steps);
	rz_pvector_fini(&steps);
	return NULL;
}

/**
 * \brief Lift what runs from \p addr until the effects it starts have landed.
 *
 * \param packet Decodes the execute packet at an address.
 * \param user Passed to \p packet.
 * \param addr Where execution starts: an execute packet, a slot inside one,
 *             which runs the rest of it (SPRUFE8B 3.5.2), or a fetch-packet
 *             header, which runs nothing.
 * \param fall Where the caller continues when the effect does not jump, or
 *             C6X_FALL_TO_END when it continues at \p end.
 * \param end Set past the code the effect covers when no branch is taken, or
 *            to 0 when the packet at \p addr could not be decoded.
 *
 * \return The effect, or NULL when the code cannot be lifted: an instruction
 *         without IL, a packet that cannot be read, or a branch to follow
 *         into a computed target.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift_window(C6xPacketFn packet, void *user, ut64 addr, ut64 fall, RZ_OUT ut64 *end) {
	rz_return_val_if_fail(packet && end, NULL);
	*end = 0;
	C6xInsn slots[C6X_FP_SLOTS];
	C6xPacketRef pkt;
	if (!packet(user, addr, slots, &pkt)) {
		return NULL;
	}
	if (pkt.n == 1 && pkt.slots[0].header) {
		// not an instruction: execution runs past it
		*end = pkt.next;
		return fall == C6X_FALL_TO_END || fall == pkt.next ? NOP() : JMP(U32((ut32)pkt.next));
	}
	C6xWin win = { packet, user, fall, C6X_WIN_PACKETS, 0, false };
	C6xWinState *st = RZ_NEW0(C6xWinState);
	if (!st) {
		return NULL;
	}
	st->pc = addr;
	RzILOpEffect *eff = c6x_win_run(&win, st, true, true);
	free(st);
	*end = win.has_end ? win.end : pkt.next;
	return eff;
}

#include <rz_il/rz_il_opbuilder_end.h>
