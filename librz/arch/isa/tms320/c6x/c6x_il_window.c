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
 * the second takes over. A result still in flight as a branch is taken lands
 * in the code at the target: that code is followed until it has when it
 * touches the register before then. Otherwise the result is written at the
 * transfer, as it is for a computed target, whose code is not in hand.
 *
 * Every conditional branch in flight doubles the paths to lift, and few of
 * them can be taken: TI's compiler clears the predicate of the branches that
 * follow one it takes, and a BDEC that has counted out leaves the later ones
 * on its counter not taken. So what the outcome of a branch tells of its
 * predicate or its counter settles the others it decides.
 *
 * A software-pipelined loop (SPRUFE8B chapter 7) starts an iteration of its
 * body every ii cycles, overlaid on those still running, until ILC runs out
 * or the condition of a SPLOOPW fails. Its periods of ii cycles are lifted as
 * the body of a repeat, every slot guarded by whether its iteration runs in
 * that period; the results in flight across a period boundary are kept in
 * locals that move up a period on every repetition, and the epilog drains
 * beside the code after the loop.
 *
 * Without SPLOOP, a loop is pipelined around its branch: the kernel branches to
 * itself every iteration, and the branch takes effect iterations later, the
 * prolog having issued those due before. Its iterations are the body of a
 * repeat as well, with the taken flags of the branches in flight moving up an
 * iteration on every repetition beside the results in flight. A loop whose one
 * branch takes effect within the iteration is run the same way when results
 * are in flight across that branch.
 */

#include <rz_util.h>
#include "c6x.h"

#include <rz_il/rz_il_opbuilder_begin.h>

/** Packets one lift may issue, over all its paths. */
#define C6X_WIN_PACKETS 256
/**
 * Packets and loop cycles one lift may issue with those of the paths it gave
 * up, and as many again in the lifts it tries where a path could end: a path
 * given up leaves the packets it issued to the others, so this is what bounds
 * the time.
 */
#define C6X_WIN_WORK 1024
/** Results in flight at once. */
#define C6X_WIN_LANDINGS 48
/** Branches in flight at once. */
#define C6X_WIN_BRANCHES 16
/** Writes of one instruction. */
#define C6X_WIN_WRITES 8
/** Cycles from a branch issuing to its target issuing: the five delay slots and one. */
#define C6X_BRANCH_CYCLES 6
/** How many packets ahead a hazard is looked for, enough for the longest delay. */
#define C6X_WIN_LOOKAHEAD 16
/** Instructions one cycle may issue: a packet, and the stages of a loop beside it. */
#define C6X_CYCLE_SLOTS 32
/** Cycles a SPLOOP body may take (SPRUFE8B 7.7), and so its execute packets. */
#define C6X_LOOP_DYNLEN 48
/** Instructions a SPLOOP body may hold: the loop buffer's fourteen packets of eight. */
#define C6X_LOOP_SLOTS 128
/** Loops one lift may run into. */
#define C6X_WIN_LOOPS 4
/** Loop cycles one lift may issue, over all its paths. */
#define C6X_LOOP_CYCLES 256
/** Execute packets the kernel of a loop pipelined around its branch may hold. */
#define C6X_BLOOP_PACKETS 16
/** Entries of the predicate log. */
#define C6X_WIN_PLOG 32
/** Addresses the paths of one lift may leave to and still be looked at. */
#define C6X_WIN_ENDS 16
/** Characters of the reason a lift keeps for having no IL. */
#define C6X_WIN_WHY 96

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

// The locals of a SPLOOP: the period it is in, its iterations, the period it
// stops before, whether a SPLOOPW still runs, and the samples of its condition
// the stage boundaries test.
#define C6X_LOOP_PERIOD "_lp"
#define C6X_LOOP_ITERS  "_ln"
#define C6X_LOOP_END    "_le"
#define C6X_LOOP_RUNS   "_lr"
static const char *const c6x_sample_names[] = { "_lw0", "_lw1", "_lw2", "_lw3" };

// The locals of a loop pipelined around its branch: whether it runs another
// iteration, and the taken flags of its branches in flight, by the iteration
// each takes effect at the start of.
#define C6X_BLOOP_RUNS "_bl"
static const char *const c6x_bq_names[C6X_BRANCH_CYCLES] = { "_bq0", "_bq1", "_bq2", "_bq3", "_bq4", "_bq5" };

/** A result in flight. */
typedef struct {
	const char *reg; ///< the register it lands in
	const char *val; ///< the local holding it
	const char *flag; ///< the local saying whether it was written, NULL when it always is
	ut32 due; ///< the cycle at whose end it lands
	bool counted; ///< a BDEC counting its register down
	bool logged; ///< in the predicate log since it issued
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
	ut8 ctr; ///< one more than the register a BDEC taken on it alone counts down, 0 for any other
	bool ctr_pred; ///< that BDEC is predicated on its counter too
	ut32 ctr_written; ///< one past the cycle of the last write to it but by such BDECs
	ut64 addr; ///< the branch instruction
	bool loop; ///< issued by a loop pipelined around its branch that has exited
} C6xFlight;

/** What a lift knows of a predicate register's value. */
typedef enum {
	C6X_PRED_ANY = 0,
	C6X_PRED_ZERO,
	C6X_PRED_NONZERO,
} C6xPredValue;

typedef enum {
	C6X_PLOG_IS, ///< a branch's outcome tells the value its cycle found
	C6X_PLOG_SET, ///< the register is written with a value of that kind
	C6X_PLOG_COPY, ///< the register is written with another predicate register
} C6xPlogKind;

/**
 * What happened to a predicate register in a cycle. TI's compiler nullifies
 * the predicate of a branch when an earlier one is taken, so what the outcome
 * of one tells of its predicate decides the other.
 */
typedef struct {
	ut32 cycle; ///< the cycle of the instruction: it reads as the cycle starts and writes at its end
	ut8 kind; ///< C6xPlogKind
	ut8 reg; ///< creg of the register
	ut8 val; ///< C6xPredValue, or the creg copied
	ut8 guard; ///< creg of the predicate it is written under, 0 for none
	bool gz; ///< that predicate's sense
	ut32 gcycle; ///< the cycle that predicate is tested in: the instruction's, which a result with delay slots lands after
} C6xPlogEntry;

/** An instruction of a SPLOOP body. */
typedef struct {
	C6xInsn insn;
	ut64 addr;
	ut8 stage; ///< the stage it issues in: its cycle in the body over ii
	ut8 offset; ///< its cycle within the stage
	ut8 unit; ///< its bit in an SPMASK unit list, UT8_MAX without a unit
	bool masked; ///< SPMASKed: issued from program memory in the first iteration only
} C6xLoopSlot;

/** An SPMASK, inhibiting buffered instructions on its units in the cycle it issues in. */
typedef struct {
	ut8 stage;
	ut8 offset;
	ut8 units;
} C6xLoopMask;

/** A SPLOOP and the body it buffers. */
typedef struct {
	C6xInsnId kind; ///< C6X_INS_SPLOOP, C6X_INS_SPLOOPD or C6X_INS_SPLOOPW
	ut8 creg; ///< the condition of a SPLOOPW
	bool z;
	ut8 ii; ///< cycles from one iteration starting to the next
	ut8 dynlen; ///< cycles of one iteration
	ut8 stages; ///< dynlen over ii, rounded up
	ut32 delay; ///< cycles of the epilog before the code after the loop issues
	ut64 post; ///< the execute packet after the SPKERNEL one
	C6xLoopSlot slot[C6X_LOOP_SLOTS];
	size_t nslot;
	C6xLoopMask mask[C6X_LOOP_DYNLEN];
	size_t nmask;
} C6xLoop;

/**
 * A loop pipelined around its branch: a kernel at the target of its own branch,
 * which takes effect some iterations after it issues, as TI's compiler builds
 * loops for C6000s without SPLOOP.
 */
typedef struct {
	ut64 start; ///< the kernel's first execute packet, its branch's target
	ut64 end; ///< the execute packet after the kernel
	ut32 len; ///< cycles of an iteration
	ut32 lag; ///< iterations from the branch issuing to it taking effect
	ut64 pc[C6X_BLOOP_PACKETS]; ///< the kernel's execute packets
	ut32 at[C6X_BLOOP_PACKETS]; ///< the cycle of an iteration each issues in
	size_t n;
	size_t outs; ///< branches out of the loop its packets issue beside its own
} C6xBLoop;

/** Whether a name a lift hands out is in use on a path. */
typedef enum {
	C6X_NAME_FREE = 0,
	C6X_NAME_USED,
	C6X_NAME_PINNED, ///< read again on the next repetition of the loop body being lifted
} C6xNameState;

/** Where one path through the lift stands. */
typedef struct {
	ut64 pc; ///< the next packet to issue
	ut32 cycle; ///< the cycle it issues in
	C6xLanding land[C6X_WIN_LANDINGS];
	size_t nland;
	C6xFlight br[C6X_WIN_BRANCHES];
	size_t nbr;
	ut8 val_state[RZ_ARRAY_SIZE(c6x_val_names)]; ///< C6xNameState of each value name
	ut8 flag_state[RZ_ARRAY_SIZE(c6x_flag_names)]; ///< and of each flag name
	ut8 taken_state[RZ_ARRAY_SIZE(c6x_taken_names)]; ///< C6xNameState of each taken flag
	ut8 target_state[RZ_ARRAY_SIZE(c6x_target_names)]; ///< and of each target
	ut32 pred_written[8]; ///< by creg: one past the cycle of the last write to the register
	ut32 ctr_written[64]; ///< by register: the same, leaving out a BDEC counting it down
	ut32 ctr_out[64]; ///< by register: one past the cycle a BDEC counting it down was not taken in, 0 for none
	ut64 ctr_out_pred; ///< by register: that BDEC was predicated on it too
	C6xPlogEntry plog[C6X_WIN_PLOG]; ///< the predicate log, by cycle, what a branch tells before the writes
	size_t nplog;
	ut32 plog_floor; ///< the cycle the log starts in
	ut8 pred_base[8]; ///< by creg: the C6xPredValue that cycle found
	const C6xLoop *epi; ///< a loop whose epilog drains beside this code, NULL when none
	ut32 epi_base; ///< the cycle the epilog's period epi_first starts in
	ut32 epi_end; ///< the cycle after its last one
	ut8 epi_first;
	ut32 idle; ///< cycles before the next packet issues while an epilog drains
	bool carried; ///< lifted on from where it could have ended, for what the path knows of a branch ahead
	bool told; ///< and that has decided a branch since
} C6xWinState;

/** Whether ops lift from an address on up to another, as c6x_ends_well() found. */
typedef struct {
	ut64 addr;
	ut64 upto;
	bool well;
} C6xEndsWell;

typedef struct {
	C6xPacketFn packet; ///< decodes the execute packet at an address
	void *user;
	ut64 fall; ///< where the caller falls through to, or C6X_FALL_TO_END
	size_t budget; ///< packets left to issue
	size_t loop_budget; ///< loop cycles left to issue
	size_t work; ///< packets and loop cycles left to issue, those of the paths given up counted
	size_t probe; ///< and left to the lifts tried where a path could end
	ut64 end; ///< where the fallthrough path leaves the code covered
	bool has_end;
	C6xLoop *loops[C6X_WIN_LOOPS]; ///< the loops run into, owned
	size_t nloops;
	bool plain; ///< every path ends where it can, whatever it knows
	bool carries; ///< a path was lifted on for what it knows
	ut64 *ends; ///< with \ref plain, where the paths leave to, when asked for
	size_t nends; ///< C6X_WIN_ENDS + 1 when there are more
	C6xEndsWell seen[C6X_WIN_ENDS]; ///< what c6x_ends_well() found
	size_t nseen;
	char why[C6X_WIN_WHY]; ///< why the last path refused does not lift
} C6xWin;

// Note why a path does not lift: for the debug log as it happens, and for the
// lift to say when it is left without IL. A lift is refused where the VM stops,
// and without the reason that is all a user of a release build can report.
static void RZ_PRINTF_CHECK(2, 3) c6x_refuse(C6xWin *win, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(win->why, sizeof(win->why), fmt, ap);
	va_end(ap);
	RZ_LOG_DEBUG("c6x: %s\n", win->why);
}

/** A register an instruction writes. */
typedef struct {
	const char *reg;
	bool cond; ///< written only on some paths through the instruction
	ut8 delay; ///< delay slots before it lands
	bool staged; ///< kept in flight rather than written in place
	bool counted; ///< a BDEC counting the register down
	bool logged; ///< in the predicate log
	const char *val; ///< the local holding it, when staged
	const char *flag; ///< the local saying whether it was written, when staged and cond
} C6xWrite;

/** An instruction of the cycle being issued. */
typedef struct {
	const C6xInsn *insn;
	ut64 addr;
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

typedef enum {
	C6X_ISSUE_FAIL,
	C6X_ISSUE_OK,
	C6X_ISSUE_LOOP, ///< not issued: the packet starts a SPLOOP
} C6xIssueResult;

static const char *c6x_name_take(const char *const *tbl, ut8 *state, size_t len, C6xNameState as) {
	for (size_t i = 0; i < len; i++) {
		if (state[i] == C6X_NAME_FREE) {
			state[i] = as;
			return tbl[i];
		}
	}
	return NULL;
}

// Set the state of \p name, a name from \p tbl; a pinned one is not freed.
static void c6x_name_set(const char *const *tbl, ut8 *state, size_t len, const char *name, C6xNameState to) {
	for (size_t i = 0; name && i < len; i++) {
		if (tbl[i] == name) {
			if (to != C6X_NAME_FREE || state[i] != C6X_NAME_PINNED) {
				state[i] = to;
			}
			return;
		}
	}
}

static const char *c6x_val_take(C6xWinState *st, C6xNameState as) {
	return c6x_name_take(c6x_val_names, st->val_state, RZ_ARRAY_SIZE(c6x_val_names), as);
}

static const char *c6x_flag_take(C6xWinState *st, C6xNameState as) {
	return c6x_name_take(c6x_flag_names, st->flag_state, RZ_ARRAY_SIZE(c6x_flag_names), as);
}

// Mark the names of \p l as \p to: free once it has landed, so that a long
// lift does not run out of them.
static void c6x_landing_names(C6xWinState *st, const C6xLanding *l, C6xNameState to) {
	c6x_name_set(c6x_val_names, st->val_state, RZ_ARRAY_SIZE(c6x_val_names), l->val, to);
	c6x_name_set(c6x_flag_names, st->flag_state, RZ_ARRAY_SIZE(c6x_flag_names), l->flag, to);
}

// Free the names of \p b, which is no longer in flight: a path through many
// branches would run out of them.
static void c6x_flight_names_free(C6xWinState *st, const C6xFlight *b) {
	c6x_name_set(c6x_taken_names, st->taken_state, RZ_ARRAY_SIZE(c6x_taken_names), b->taken, C6X_NAME_FREE);
	c6x_name_set(c6x_target_names, st->target_state, RZ_ARRAY_SIZE(c6x_target_names), b->target, C6X_NAME_FREE);
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

// The index of the general register \p reg, A0 to A31 then B0 to B31, UT8_MAX
// for any other.
static ut8 c6x_gpr_index(const char *reg) {
	if ((reg[0] != 'a' && reg[0] != 'b') || !IS_DIGIT(reg[1])) {
		return UT8_MAX;
	}
	ut32 n = reg[1] - '0';
	if (reg[2]) {
		if (!IS_DIGIT(reg[2]) || reg[3]) {
			return UT8_MAX;
		}
		n = n * 10 + (reg[2] - '0');
	}
	return n < 32 ? (reg[0] == 'b' ? 32 : 0) + n : UT8_MAX;
}

// The register \p insn counts down when it is a BDEC taken on that register
// alone: unpredicated, or predicated on the counter not being zero. UT8_MAX
// for any other instruction.
static ut8 c6x_counter(const C6xInsn *insn, RZ_OUT bool *pred) {
	*pred = false;
	if (insn->id != C6X_INS_BDEC || insn->nops < 2 || insn->ops[1].kind != C6X_OP_REG) {
		return UT8_MAX;
	}
	const char *reg = c6x_il_reg(insn->ops[1].v.reg.side, insn->ops[1].v.reg.num);
	*pred = insn->creg;
	if (insn->creg && (insn->z || !RZ_STR_EQ(c6x_pred_reg_name(insn->creg), reg))) {
		return UT8_MAX;
	}
	return c6x_gpr_index(reg);
}

// Forget what is known of the predicate registers, as where cycles are counted anew.
static void c6x_plog_reset(C6xWinState *st) {
	st->nplog = 0;
	st->plog_floor = 0;
	memset(st->pred_base, C6X_PRED_ANY, sizeof(st->pred_base));
	for (size_t i = 0; i < st->nland; i++) {
		// the log has what is in flight no longer
		st->land[i].logged = false;
	}
}

// What is known of the predicate registers as \p cycle starts, into \p v by creg.
static void c6x_plog_replay(const C6xWinState *st, ut32 cycle, RZ_OUT ut8 *v) {
	ut8 found[8]; // what the cycle of the entry found
	memcpy(v, st->pred_base, sizeof(st->pred_base));
	memcpy(found, v, sizeof(found));
	ut32 at = st->plog_floor;
	for (size_t i = 0; i < st->nplog; i++) {
		const C6xPlogEntry *e = &st->plog[i];
		if (e->cycle > cycle || (e->cycle == cycle && e->kind != C6X_PLOG_IS)) {
			break;
		}
		if (e->cycle != at) {
			memcpy(found, v, sizeof(found));
			at = e->cycle;
		}
		if (e->kind == C6X_PLOG_IS) {
			v[e->reg] = found[e->reg] = e->val;
			continue;
		}
		ut8 nv = e->kind == C6X_PLOG_COPY ? found[e->val] : e->val;
		ut8 g = e->guard ? found[e->guard] : C6X_PRED_ANY;
		if (e->guard && e->gcycle != e->cycle) {
			// tested cycles before it lands, which the log may not reach back to
			ut8 then[8] = { 0 };
			if (e->gcycle >= st->plog_floor) {
				c6x_plog_replay(st, e->gcycle, then);
			}
			g = then[e->guard];
		}
		if (e->guard && g == C6X_PRED_ANY) {
			// written or not
			if (v[e->reg] != nv) {
				v[e->reg] = C6X_PRED_ANY;
			}
		} else if (!e->guard || (g == C6X_PRED_NONZERO) != e->gz) {
			v[e->reg] = nv;
		}
	}
}

// Start the log at \p cycle, which nothing a branch may yet tell is older than.
static void c6x_plog_fold(C6xWinState *st, ut32 cycle) {
	if (cycle <= st->plog_floor) {
		return;
	}
	ut8 v[8];
	c6x_plog_replay(st, cycle, v);
	size_t keep = 0;
	for (size_t i = 0; i < st->nplog; i++) {
		const C6xPlogEntry *e = &st->plog[i];
		if (e->cycle > cycle || (e->cycle == cycle && e->kind != C6X_PLOG_IS)) {
			st->plog[keep++] = *e;
		}
	}
	st->nplog = keep;
	st->plog_floor = cycle;
	memcpy(st->pred_base, v, sizeof(st->pred_base));
}

// Add \p e to the log in the order of its cycle. Returns whether the log
// holds it: a write before the cycle the log starts in is not kept.
static bool c6x_plog_add(C6xWinState *st, C6xPlogEntry e) {
	if (st->nplog == C6X_WIN_PLOG) {
		// start over past everything logged, knowing nothing
		ut32 last = RZ_MAX(st->plog[st->nplog - 1].cycle, e.cycle);
		c6x_plog_reset(st);
		st->plog_floor = last + 1;
	}
	if (e.cycle < st->plog_floor) {
		if (e.kind != C6X_PLOG_IS) {
			st->pred_base[e.reg] = C6X_PRED_ANY;
		} else if (st->pred_written[e.reg] <= e.cycle) {
			// not written since, so the log's first cycle found the same
			st->pred_base[e.reg] = e.val;
		}
		return false;
	}
	size_t at = 0;
	while (at < st->nplog && (st->plog[at].cycle < e.cycle || (st->plog[at].cycle == e.cycle && (e.kind != C6X_PLOG_IS || st->plog[at].kind == C6X_PLOG_IS)))) {
		at++;
	}
	memmove(&st->plog[at + 1], &st->plog[at], (st->nplog - at) * sizeof(C6xPlogEntry));
	st->plog[at] = e;
	st->nplog++;
	return true;
}

// What is known of the predicate register \p creg as \p cycle starts.
static C6xPredValue c6x_pred_known(const C6xWinState *st, ut8 creg, ut32 cycle) {
	const char *reg = c6x_pred_reg_name(creg);
	if (!reg) {
		return C6X_PRED_ANY;
	}
	for (size_t i = 0; i < st->nland; i++) {
		// a result landing before then is not in the log yet
		if (st->land[i].due < cycle && !st->land[i].logged && RZ_STR_EQ(st->land[i].reg, reg)) {
			return C6X_PRED_ANY;
		}
	}
	ut8 v[8];
	c6x_plog_replay(st, cycle, v);
	return v[creg & 7];
}

// Note in the log that the branch \p b on a predicate alone was taken, or not.
static void c6x_plog_tell(C6xWinState *st, const C6xFlight *b, bool taken) {
	if (b->creg) {
		C6xPlogEntry e = { b->issued, C6X_PLOG_IS, b->creg, taken != b->z ? C6X_PRED_NONZERO : C6X_PRED_ZERO, 0, false, b->issued };
		c6x_plog_add(st, e);
	}
}

// Note in the log that \p insn, issuing in \p cycle, writes the predicate
// register \p creg at the end of cycle \p at: with a constant or another
// predicate register when \p known and it moves one, with anything otherwise.
// Its own predicate is tested as it issues, also when the result lands later.
// Returns whether the log holds the write, or the instruction does not issue.
static bool c6x_plog_write(C6xWinState *st, RZ_NULLABLE const C6xInsn *insn, ut8 creg, ut32 cycle, ut32 at, bool known) {
	C6xPlogEntry e = { at, C6X_PLOG_SET, creg, C6X_PRED_ANY, 0, false, cycle };
	if (known && at != cycle) {
		C6xPredValue g = insn->creg ? c6x_pred_known(st, insn->creg, cycle) : C6X_PRED_ANY;
		if (g != C6X_PRED_ANY && (g == C6X_PRED_NONZERO) == insn->z) {
			return true;
		}
		if (g == C6X_PRED_ANY) {
			e.guard = insn->creg;
			e.gz = insn->z;
		}
	} else if (known) {
		e.guard = insn->creg;
		e.gz = insn->z;
		const C6xOperand *src = &insn->ops[0];
		if (insn->id == C6X_INS_ZERO) {
			e.val = C6X_PRED_ZERO;
		} else if (insn->id == C6X_INS_MVK && insn->nops == 2 && src->kind == C6X_OP_IMM) {
			e.val = src->v.imm.value ? C6X_PRED_NONZERO : C6X_PRED_ZERO;
		} else if (insn->id == C6X_INS_MV && insn->nops == 2 && src->kind == C6X_OP_REG) {
			ut8 from = c6x_creg_of(c6x_il_reg(src->v.reg.side, src->v.reg.num));
			if (from) {
				e.kind = C6X_PLOG_COPY;
				e.val = from;
			}
		}
	}
	return c6x_plog_add(st, e);
}

// Note that \p reg was written in \p cycle, for telling whether two branches
// tested the same value: of their predicate, or of the counter of a BDEC,
// which its own counting down with \p counted leaves as a later one finds it
// when it is not taken.
static void c6x_note_write(C6xWinState *st, const char *reg, ut32 cycle, bool counted) {
	ut8 c = c6x_creg_of(reg);
	if (c && st->pred_written[c] < cycle + 1) {
		st->pred_written[c] = cycle + 1;
	}
	ut8 g = c6x_gpr_index(reg);
	if (!counted && g != UT8_MAX && st->ctr_written[g] < cycle + 1) {
		st->ctr_written[g] = cycle + 1;
	}
}

// Whether \p b and \p o are taken on one value of one predicate register: it
// was not written between their tests.
static bool c6x_same_test(const C6xFlight *b, const C6xFlight *o) {
	const C6xFlight *early = b->issued <= o->issued ? b : o;
	const C6xFlight *late = early == b ? o : b;
	return b->creg && b->creg == o->creg && late->pred_written <= early->issued;
}

// Whether \p o, a BDEC issued after the BDEC \p b on the same counter, is not
// taken because \p b was not: a counter below zero, or zero under the
// predicate, stays so until something else writes it.
static bool c6x_counted_out(const C6xFlight *b, const C6xFlight *o) {
	return b->ctr && b->ctr == o->ctr && (o->ctr_pred || !b->ctr_pred) &&
		o->issued > b->issued && o->ctr_written <= b->issued;
}

// Note that the BDEC \p b was not taken: nor is a later one on its counter,
// until something else writes it.
static void c6x_note_counted_out(C6xWinState *st, const C6xFlight *b) {
	if (!b->ctr) {
		return;
	}
	ut8 r = b->ctr - 1;
	if (st->ctr_out[r] && st->ctr_written[r] < st->ctr_out[r] && st->ctr_out[r] <= b->issued + 1) {
		return; // an earlier one still holds
	}
	st->ctr_out[r] = b->issued + 1;
	st->ctr_out_pred = (st->ctr_out_pred & ~(1ull << r)) | ((ut64)b->ctr_pred << r);
}

// Whether a BDEC on register \p r, predicated on it with \p pred, issuing now
// is known not to be taken.
static bool c6x_is_counted_out(const C6xWinState *st, ut8 r, bool pred) {
	return st->ctr_out[r] && st->ctr_written[r] < st->ctr_out[r] && (pred || !((st->ctr_out_pred >> r) & 1));
}

// Settle the branches in flight that the outcome of \p b decides: what it tells
// of its predicate, and of those written from it since, takes the ones on a
// value now known and drops the others, as it does the BDECs a BDEC not taken
// counts out. Left undecided, a path the IL cannot take would still be lifted,
// and analysis would find edges that are not there.
static void c6x_settle(C6xWinState *st, const C6xFlight *b, bool taken) {
	if (!taken) {
		c6x_note_counted_out(st, b);
	}
	c6x_plog_tell(st, b, taken);
	size_t keep = 0;
	for (size_t i = 0; i < st->nbr; i++) {
		C6xFlight o = st->br[i];
		if (!taken && c6x_counted_out(b, &o)) {
			c6x_flight_names_free(st, &o);
			continue;
		}
		// what the outcome tells of its predicate, through the writes since
		C6xPredValue v = o.creg && o.taken ? c6x_pred_known(st, o.creg, o.issued) : C6X_PRED_ANY;
		if (c6x_same_test(b, &o)) {
			v = taken != b->z ? C6X_PRED_NONZERO : C6X_PRED_ZERO;
		}
		if (v != C6X_PRED_ANY) {
			c6x_name_set(c6x_taken_names, st->taken_state, RZ_ARRAY_SIZE(c6x_taken_names), o.taken, C6X_NAME_FREE);
			if ((v == C6X_PRED_NONZERO) == o.z) {
				c6x_flight_names_free(st, &o);
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

// Whether a packet about to issue holds a branch \p st knows is not taken: on a
// predicate register whose value it knows, or a BDEC whose counter has run
// out; \p at receives that packet's address. A lift ending before it would
// lose that, and the code there may not lift without: the kernel of a loop is
// reached this way when its branches were cleared for it to run once. What
// issues before the branch may still write the register, so a lift that goes
// on for it has to get there knowing.
static bool c6x_known_ahead(C6xWin *win, const C6xWinState *st, RZ_OUT ut64 *at) {
	ut64 pc = st->pc;
	*at = pc;
	for (size_t k = 0; k < C6X_BRANCH_CYCLES; k++) {
		C6xInsn ins[C6X_FP_SLOTS];
		C6xPacketRef p;
		size_t n = win->packet(win->user, pc, ins, &p);
		if (!n) {
			return false;
		}
		for (size_t i = 0; i < n; i++) {
			const C6xInsn *x = &ins[i];
			bool pred;
			ut8 ctr = c6x_counter(x, &pred);
			if (ctr != UT8_MAX && c6x_is_counted_out(st, ctr, pred)) {
				*at = pc;
				return true;
			}
			if ((x->id != C6X_INS_B && x->id != C6X_INS_BNOP) || !x->creg) {
				continue;
			}
			bool flying = false;
			for (size_t l = 0; l < st->nland && !flying; l++) {
				flying = RZ_STR_EQ(st->land[l].reg, c6x_pred_reg_name(x->creg));
			}
			C6xPredValue v = flying ? C6X_PRED_ANY : c6x_pred_known(st, x->creg, st->cycle);
			if (v != C6X_PRED_ANY && (v == C6X_PRED_NONZERO) == x->z) {
				*at = pc;
				return true;
			}
		}
		pc = p.next;
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
		c6x_note_write(st, st->land[best].reg, st->land[best].due, st->land[best].counted);
		ut8 creg = c6x_creg_of(st->land[best].reg);
		if (creg && !st->land[best].logged) {
			c6x_plog_write(st, NULL, creg, st->land[best].due, st->land[best].due, false);
		}
		c6x_landing_names(st, &st->land[best], C6X_NAME_FREE);
		memmove(&st->land[best], &st->land[best + 1], (st->nland - best - 1) * sizeof(C6xLanding));
		st->nland--;
	}
}

// Every result in flight, in the order they land, leaving the state as it is.
static void c6x_land_copy(const C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps) {
	C6xWinState *tmp = RZ_NEW0(C6xWinState);
	if (!tmp) {
		return;
	}
	tmp->nland = st->nland;
	memcpy(tmp->land, st->land, st->nland * sizeof(C6xLanding));
	c6x_land_before(tmp, UT32_MAX, steps);
	free(tmp);
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

// Issue the \p n instructions of cycle st->cycle, which own their bodies: every
// one runs against the state the cycle found, and what lands later or is read
// again within the cycle goes into flight. A delayed result goes into flight
// when the code fetched from \p ahead, issuing from \p next_cycle on, touches
// it before it lands, or with \p blind, when that code is not all there is.
static bool c6x_issue_cycle(C6xWin *win, C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps, C6xIssue *is, size_t n, ut64 ahead, ut32 next_cycle, bool blind) {
	ut32 cycle = st->cycle;
	size_t jumps = 0;
	if (!blind) {
		// no branch in flight tells of a cycle before the one it issued in
		ut32 floor = cycle;
		for (size_t i = 0; i < st->nbr; i++) {
			floor = RZ_MIN(floor, st->br[i].issued);
		}
		c6x_plog_fold(st, floor);
	}
	for (size_t o = 0; o < n; o++) {
		C6xIssue *x = &is[o];
		if (c6x_effect_jumps(x->body)) {
			x->taken = c6x_name_take(c6x_taken_names, st->taken_state, RZ_ARRAY_SIZE(c6x_taken_names), C6X_NAME_USED);
			x->target = c6x_name_take(c6x_target_names, st->target_state, RZ_ARRAY_SIZE(c6x_target_names), C6X_NAME_USED);
			bool ok = x->taken && x->target;
			x->body = c6x_capture_jump(x->body, false, x, &ok);
			if (!ok || st->nbr + jumps >= C6X_WIN_BRANCHES) {
				c6x_refuse(win, "too many branches in flight at 0x%" PFMT64x "", x->addr);
				goto fail;
			}
			jumps++;
		}
		if (!c6x_collect_writes(x->body, false, x)) {
			goto fail;
		}
	}
	// the first cycle a branch, in flight or of this cycle, may fetch from its target
	ut32 turn = jumps ? cycle + C6X_BRANCH_CYCLES : UT32_MAX;
	for (size_t i = 0; i < st->nbr; i++) {
		turn = RZ_MIN(turn, st->br[i].issued + C6X_BRANCH_CYCLES);
	}
	// A write is staged -- kept in a local until it lands -- when anything could
	// see it early: a later slot of the cycle touching the register, a packet
	// before it lands doing so, which the code at a branch's target may, or an
	// earlier result still in flight to it.
	for (size_t o = 0; o < n; o++) {
		bool pred;
		ut8 ctr = c6x_counter(is[o].insn, &pred);
		for (size_t k = 0; k < is[o].nw; k++) {
			C6xWrite *w = &is[o].w[k];
			w->counted = ctr != UT8_MAX && c6x_gpr_index(w->reg) == ctr;
			bool stage = false;
			for (size_t p = o + 1; p < n && !stage; p++) {
				stage = c6x_touches(is[p].insn, w->reg);
			}
			for (size_t l = 0; l < st->nland && !stage; l++) {
				stage = RZ_STR_EQ(st->land[l].reg, w->reg);
			}
			if (!stage && w->delay) {
				stage = blind || turn <= cycle + w->delay || c6x_touched_ahead(win, ahead, next_cycle, w->reg, cycle + w->delay);
			}
			w->staged = stage;
		}
	}
	// every writer of a staged register is staged, so that they land in order
	for (size_t o = 0; o < n; o++) {
		for (size_t k = 0; k < is[o].nw; k++) {
			for (size_t p = 0; p < n; p++) {
				for (size_t q = 0; q < is[p].nw; q++) {
					if (is[p].w[q].staged && RZ_STR_EQ(is[p].w[q].reg, is[o].w[k].reg)) {
						is[o].w[k].staged = true;
					}
				}
			}
		}
	}
	// snapshots of the staged registers, which each slot is run against
	const char *staged[RZ_ARRAY_SIZE(c6x_snap_names)];
	const char *snap[RZ_ARRAY_SIZE(c6x_snap_names)];
	bool dirty[RZ_ARRAY_SIZE(c6x_snap_names)] = { 0 };
	size_t nstaged = 0;
	for (size_t o = 0; o < n; o++) {
		for (size_t k = 0; k < is[o].nw; k++) {
			C6xWrite *w = &is[o].w[k];
			if (!w->staged) {
				continue;
			}
			w->val = c6x_val_take(st, C6X_NAME_USED);
			w->flag = w->cond ? c6x_flag_take(st, C6X_NAME_USED) : NULL;
			if (!w->val || (w->cond && !w->flag)) {
				c6x_refuse(win, "too many results in flight at 0x%" PFMT64x "", st->pc);
				goto fail;
			}
			size_t j = 0;
			while (j < nstaged && !RZ_STR_EQ(staged[j], w->reg)) {
				j++;
			}
			if (j == nstaged) {
				if (nstaged >= RZ_ARRAY_SIZE(c6x_snap_names)) {
					c6x_refuse(win, "too many results in flight at 0x%" PFMT64x "", st->pc);
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
	for (size_t o = 0; o < n; o++) {
		C6xIssue *x = &is[o];
		// run against the state the cycle found
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
			ut8 creg = c6x_creg_of(w->reg);
			if (creg && (!w->delay || (!blind && x->insn->creg))) {
				// A loop's slot may not issue at all, so what it writes is not
				// known. A result with delay slots is logged as it issues for
				// its predicate, which may tell later that it never did.
				w->logged = c6x_plog_write(st, x->insn, creg, cycle, cycle + w->delay, !blind);
			}
			if (!w->staged) {
				// written in place, it still changes in the cycle it lands in
				if (creg && !w->logged) {
					c6x_plog_write(st, NULL, creg, cycle + w->delay, cycle + w->delay, false);
				}
				c6x_note_write(st, w->reg, cycle + w->delay, w->counted);
				continue;
			}
			rz_pvector_push(steps, SETL(w->val, VARG(w->reg)));
			for (size_t j = 0; j < nstaged; j++) {
				dirty[j] |= RZ_STR_EQ(staged[j], w->reg);
			}
			if (st->nland >= C6X_WIN_LANDINGS) {
				c6x_refuse(win, "too many results in flight at 0x%" PFMT64x "", st->pc);
				goto fail;
			}
			C6xLanding *l = &st->land[st->nland++];
			l->reg = w->reg;
			l->val = w->val;
			l->flag = w->flag;
			l->due = cycle + w->delay;
			l->counted = w->counted;
			l->logged = w->logged;
		}
		bool cpred = false;
		ut8 ctr = x->jumps ? c6x_counter(x->insn, &cpred) : UT8_MAX;
		// only B and BNOP are taken on their predicate alone
		bool plain = x->insn->id == C6X_INS_B || x->insn->id == C6X_INS_BNOP;
		// what is known of its predicate decides a branch as it issues
		C6xPredValue pv = C6X_PRED_ANY;
		if (x->jumps && x->jump_cond && x->insn->creg && !blind) {
			pv = c6x_pred_known(st, x->insn->creg, cycle);
		}
		bool never = pv != C6X_PRED_ANY && (pv == C6X_PRED_NONZERO) == x->insn->z;
		bool always = pv != C6X_PRED_ANY && !never && plain;
		never = never || (x->jumps && x->jump_cond && ctr != UT8_MAX && c6x_is_counted_out(st, ctr, cpred));
		st->told = st->told || (x->jumps && (never || always));
		if (x->jumps && !never) {
			C6xFlight *b = &st->br[st->nbr++];
			b->issued = cycle;
			b->taken = x->jump_cond && !always ? x->taken : NULL;
			b->target = x->target_is_const ? NULL : x->target;
			b->target_const = x->target_const;
			b->creg = plain && x->jump_cond && !always ? x->insn->creg : 0;
			b->z = x->insn->z;
			b->pred_written = b->creg ? st->pred_written[b->creg & 7] : 0;
			b->ctr_pred = cpred;
			b->ctr = ctr != UT8_MAX && x->jump_cond ? ctr + 1 : 0;
			b->ctr_written = b->ctr ? st->ctr_written[ctr] : 0;
			b->addr = x->addr;
			b->loop = false;
			if (always) {
				x->jump_cond = false; // it keeps no flag
			}
		} else if (x->jumps) {
			x->jump_cond = false; // not taken: it keeps no name
			x->target_is_const = true;
		}
		if (x->jumps && !x->jump_cond) {
			c6x_name_set(c6x_taken_names, st->taken_state, RZ_ARRAY_SIZE(c6x_taken_names), x->taken, C6X_NAME_FREE);
		}
		if (x->jumps && x->target_is_const) {
			c6x_name_set(c6x_target_names, st->target_state, RZ_ARRAY_SIZE(c6x_target_names), x->target, C6X_NAME_FREE);
		}
	}
	// the cycle's own writes land at its end at the earliest
	for (size_t j = 0; j < nstaged; j++) {
		if (dirty[j]) {
			rz_pvector_push(steps, SETG(staged[j], VARL(snap[j])));
		}
	}
	return true;
fail:
	c6x_issues_fini(is, n);
	return false;
}

// Put \p body, what the instruction \p insn at \p addr or a part of it does
// when \p guard holds, into the cycle being put together. With \p at_once its
// writes land with the cycle.
static bool c6x_cycle_put(C6xWin *win, C6xIssue *is, size_t *n, const C6xInsn *insn, ut64 addr, RZ_OWN RzILOpEffect *body, RZ_NULLABLE RZ_OWN RzILOpPure *guard, bool at_once) {
	if (!body) {
		c6x_refuse(win, "no IL for %s at 0x%" PFMT64x "", rz_str_get_null(c6x_ins_name(insn->id)), addr);
		rz_il_op_pure_free(guard);
		return false;
	}
	if (*n >= C6X_CYCLE_SLOTS) {
		c6x_refuse(win, "too many instructions in the cycle at 0x%" PFMT64x "", addr);
		rz_il_op_effect_free(body);
		rz_il_op_pure_free(guard);
		return false;
	}
	C6xIssue *x = &is[(*n)++];
	memset(x, 0, sizeof(*x));
	x->insn = insn;
	x->addr = addr;
	x->body = guard ? BRANCH(guard, body, NOP()) : body;
	x->at_once = at_once;
	return true;
}

// Add the instruction \p insn at \p addr, of the packet \p pkt when it is
// issued from one, to the cycle being put together; it runs when \p guard holds.
static bool c6x_cycle_add(C6xWin *win, C6xIssue *is, size_t *n, const C6xInsn *insn, ut64 addr, RZ_NULLABLE const C6xPacketRef *pkt, RZ_NULLABLE RZ_OWN RzILOpPure *guard) {
	if (!c6x_load_into_base(insn)) {
		RzILOpEffect *body = pkt ? c6x_slot_body(insn, addr, pkt) : c6x_lift(insn, addr);
		return c6x_cycle_put(win, is, n, insn, addr, body, guard, false);
	}
	// It writes the register twice, so it issues as two: the address lands with
	// the cycle, what it loads after the delay slots.
	RzILOpPure *again = guard ? rz_il_op_pure_dup(guard) : NULL;
	if (!c6x_cycle_put(win, is, n, insn, addr, c6x_lift_load_part(insn, addr, true), guard, true)) {
		rz_il_op_pure_free(again);
		return false;
	}
	return c6x_cycle_put(win, is, n, insn, addr, c6x_lift_load_part(insn, addr, false), again, false);
}

// Whether \p insn starts a software-pipelined loop.
static bool c6x_is_sploop(const C6xInsn *insn) {
	return insn->id == C6X_INS_SPLOOP || insn->id == C6X_INS_SPLOOPD || insn->id == C6X_INS_SPLOOPW;
}

// The slots of the epilog draining in cycle st->cycle: the later stages of the
// last iterations, period by period.
static size_t c6x_epi_slots(const C6xWinState *st, const C6xLoopSlot **out, size_t max) {
	const C6xLoop *lp = st->epi;
	if (!lp || st->cycle >= st->epi_end) {
		return 0;
	}
	ut32 t = st->cycle - st->epi_base;
	ut32 e = st->epi_first + t / lp->ii;
	ut32 r = t % lp->ii;
	size_t n = 0;
	for (size_t i = 0; i < lp->nslot && n < max; i++) {
		const C6xLoopSlot *ls = &lp->slot[i];
		if (!ls->masked && ls->offset == r && ls->stage > e) {
			out[n++] = ls;
		}
	}
	return n;
}

// Put the epilog slots of cycle st->cycle, whose stores go last, into the cycle.
static bool c6x_cycle_add_epi(C6xWin *win, const C6xWinState *st, C6xIssue *is, size_t *n, bool stores) {
	const C6xLoopSlot *ls[C6X_CYCLE_SLOTS];
	size_t m = c6x_epi_slots(st, ls, RZ_ARRAY_SIZE(ls));
	for (size_t i = 0; i < m; i++) {
		if (c6x_writes_memory(&ls[i]->insn) == stores &&
			!c6x_cycle_add(win, is, n, &ls[i]->insn, ls[i]->addr, NULL, NULL)) {
			return false;
		}
	}
	return true;
}

// Move on to the next cycle, dropping the epilog once it has drained.
static void c6x_next_cycle(C6xWinState *st, ut32 cycles) {
	st->cycle += cycles;
	if (st->epi && st->cycle >= st->epi_end) {
		st->epi = NULL;
	}
}

// Issue the execute packet at st->pc from the slot there on, in cycle
// st->cycle, beside the epilog of a loop draining in it.
static C6xIssueResult c6x_win_issue(C6xWin *win, C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps) {
	if (!win->budget || !win->work) {
		c6x_refuse(win, "lifting at 0x%" PFMT64x " issues more packets than one lift may", st->pc);
		return C6X_ISSUE_FAIL;
	}
	C6xInsn slots[C6X_FP_SLOTS];
	C6xPacketRef pkt;
	size_t n = win->packet(win->user, st->pc, slots, &pkt);
	if (!n || (pkt.n == 1 && pkt.slots[0].header)) {
		c6x_refuse(win, "no execute packet to lift at 0x%" PFMT64x "", st->pc);
		return C6X_ISSUE_FAIL;
	}
	size_t first = 0;
	while (first < n && pkt.slots[first].addr != st->pc) {
		first++;
	}
	if (first == n) {
		return C6X_ISSUE_FAIL;
	}
	if (c6x_is_sploop(&slots[first])) {
		return C6X_ISSUE_LOOP;
	}
	win->budget--;
	win->work--;
	ut32 extra = c6x_packet_cycles(slots, first, n) - 1;
	C6xIssue *is = RZ_NEWS0(C6xIssue, C6X_CYCLE_SLOTS);
	if (!is) {
		return C6X_ISSUE_FAIL;
	}
	// a load and a store to the same location in one cycle load the old value
	// (SPRUFE8B 4.2), so the slots reading memory run first
	size_t nis = 0;
	bool ok = true;
	for (int stores = 0; stores < 2 && ok; stores++) {
		for (size_t i = first; i < n && ok; i++) {
			if (c6x_writes_memory(&slots[i]) == stores) {
				ok = c6x_cycle_add(win, is, &nis, &slots[i], pkt.slots[i].addr, &pkt, NULL);
			}
		}
		ok = ok && c6x_cycle_add_epi(win, st, is, &nis, stores);
	}
	// while an epilog drains, every cycle of a multi-cycle NOP issues its slots
	bool draining = st->epi;
	ut32 next_cycle = st->cycle + 1 + (draining ? 0 : extra);
	ok = ok && c6x_issue_cycle(win, st, steps, is, nis, pkt.next, next_cycle, draining);
	if (!ok) {
		c6x_issues_fini(is, nis);
		free(is);
		return C6X_ISSUE_FAIL;
	}
	free(is);
	st->pc = pkt.next;
	st->idle = draining ? extra : 0;
	c6x_next_cycle(st, next_cycle - st->cycle);
	return C6X_ISSUE_OK;
}

// Issue a cycle no packet issues in, the epilog of a loop draining in it.
static bool c6x_win_idle(C6xWin *win, C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps) {
	C6xIssue *is = RZ_NEWS0(C6xIssue, C6X_CYCLE_SLOTS);
	if (!is) {
		return false;
	}
	size_t nis = 0;
	bool ok = c6x_cycle_add_epi(win, st, is, &nis, false) && c6x_cycle_add_epi(win, st, is, &nis, true) &&
		c6x_issue_cycle(win, st, steps, is, nis, 0, st->cycle + 1, true);
	if (!ok) {
		c6x_issues_fini(is, nis);
	}
	free(is);
	st->idle--;
	c6x_next_cycle(st, 1);
	return ok;
}

static RzILOpEffect *c6x_flight_jump(const C6xFlight *b) {
	return JMP(b->target ? VARL(b->target) : U32((ut32)b->target_const));
}

static RzILOpEffect *c6x_win_run(C6xWin *win, C6xWinState *st, bool main_path, bool issue_first);
static bool c6x_bloop_find(C6xWin *win, const C6xWinState *st, RZ_NULLABLE const C6xFlight *own, C6xBLoop *lp);
static RzILOpEffect *c6x_win_bloop(C6xWin *win, C6xWinState *st, const C6xBLoop *lp);

/** What a path that may fail to lift uses up of a lift. */
typedef struct {
	size_t budget;
	size_t loop_budget;
	size_t nloops;
	ut64 end;
	bool has_end;
} C6xWinMark;

static void c6x_win_mark(const C6xWin *win, RZ_OUT C6xWinMark *m) {
	m->budget = win->budget;
	m->loop_budget = win->loop_budget;
	m->nloops = win->nloops;
	m->end = win->end;
	m->has_end = win->has_end;
}

// Give back what a path that did not lift used up since \p m was taken.
static void c6x_win_rewind(C6xWin *win, const C6xWinMark *m) {
	win->budget = m->budget;
	win->loop_budget = m->loop_budget;
	while (win->nloops > m->nloops) {
		free(win->loops[--win->nloops]);
	}
	win->end = m->end;
	win->has_end = m->has_end;
}

// Follow control taken to \p st, a path of its own: the loop there when it is
// pipelined around its branch, or \p own, which brought control there, is the
// one branch of a loop, and its packets otherwise.
static RzILOpEffect *c6x_win_follow(C6xWin *win, C6xWinState *st, RZ_NULLABLE const C6xFlight *own) {
	C6xBLoop bl;
	if (c6x_bloop_find(win, st, own, &bl)) {
		C6xWinState *ls = RZ_NEW(C6xWinState);
		if (!ls) {
			return NULL;
		}
		*ls = *st;
		RzILOpEffect *loop = c6x_win_bloop(win, ls, &bl);
		free(ls);
		if (loop) {
			return loop;
		}
	}
	return c6x_win_run(win, st, false, true);
}

static void c6x_win_init(C6xWin *win, C6xPacketFn packet, void *user, ut64 fall, bool plain);
static RzILOpEffect *c6x_window(C6xWin *win, ut64 addr, RZ_OUT ut64 *end);

// Note that a path of a plain lift leaves to \p addr.
static void c6x_end_note(C6xWin *win, ut64 addr) {
	if (!win->ends || win->nends > C6X_WIN_ENDS) {
		return;
	}
	for (size_t i = 0; i < win->nends; i++) {
		if (win->ends[i] == addr) {
			return;
		}
	}
	if (win->nends < C6X_WIN_ENDS) {
		win->ends[win->nends] = addr;
	}
	win->nends++;
}

// Whether an op lifts at \p addr knowing nothing and ending wherever it can,
// within the packets of one lift and what \p win has left for trying; \p ends
// receives where its paths leave to, \p n how many they are.
static bool c6x_lifts_plain(C6xWin *win, ut64 addr, RZ_NULLABLE ut64 *ends, RZ_NULLABLE size_t *n) {
	C6xWin sub;
	c6x_win_init(&sub, win->packet, win->user, C6X_FALL_TO_END, true);
	sub.ends = ends;
	size_t share = RZ_MIN(win->probe, C6X_WIN_PACKETS);
	sub.work = share;
	ut64 end = 0;
	RzILOpEffect *eff = c6x_window(&sub, addr, &end);
	win->probe -= share - sub.work;
	if (n) {
		*n = sub.nends;
	}
	bool lifts = eff;
	rz_il_op_effect_free(eff);
	return lifts;
}

// Whether ops lift from \p addr on without what a path arriving there knows of
// the branch in the packet at \p upto: the op starting there, those starting
// where its paths leave to, and on from the ones that start no further than
// that packet. A path that knows what decides a branch ahead ends there only
// then. Going on for it regardless moves the end of the op to wherever that
// knowledge runs out, which may be between the branches of a prolog, where an
// op takes all of them into flight at once and so may not lift.
static bool c6x_ends_well(C6xWin *win, ut64 addr, ut64 upto) {
	for (size_t i = 0; i < win->nseen; i++) {
		if (win->seen[i].addr == addr && win->seen[i].upto == upto) {
			return win->seen[i].well;
		}
	}
	ut64 todo[C6X_WIN_ENDS] = { addr };
	size_t n = 1;
	bool well = true;
	for (size_t done = 0; well && done < n; done++) {
		ut64 ends[C6X_WIN_ENDS];
		size_t ne = 0;
		bool leads = todo[done] >= addr && todo[done] <= upto;
		well = c6x_lifts_plain(win, todo[done], leads ? ends : NULL, &ne) && ne <= C6X_WIN_ENDS;
		for (size_t i = 0; well && leads && i < ne; i++) {
			size_t j = 0;
			while (j < n && todo[j] != ends[i]) {
				j++;
			}
			if (j < n) {
				continue;
			}
			well = n < C6X_WIN_ENDS;
			if (well) {
				todo[n++] = ends[i];
			}
		}
	}
	if (win->nseen < C6X_WIN_ENDS) {
		win->seen[win->nseen++] = (C6xEndsWell){ addr, upto, well };
	}
	return well;
}

// The transfer of branch \p b out of the steps so far, when taken. A later
// branch still in flight is followed into the target until it takes over, or
// runs the loop the target starts when it is pipelined around its branch. With
// none taken, control leaves with every result in flight written, unless the
// code at the target touches one before it lands: then that code is followed
// until they have, as a loop when \p b is its one branch. It is followed past
// a branch the path knows is not taken as well, when the ops from the target on
// do not lift without knowing. A loop buffer goes idle once a branch is taken,
// so its epilog stops draining.
static RzILOpEffect *c6x_win_taken(C6xWin *win, const C6xWinState *st, const C6xFlight *b, ut32 at) {
	RzPVector steps;
	rz_pvector_init(&steps, NULL);
	c6x_land_copy(st, &steps);
	RzILOpEffect *leave = c6x_seal(&steps, c6x_flight_jump(b));
	rz_pvector_fini(&steps);
	if (!leave) {
		return NULL;
	}
	if (b->target || b->loop) {
		// A computed target is not in hand, and a pipelined loop is not run again
		// once one of its branches was not taken. The branches still in flight
		// are dropped, which is wrong when one of them is taken too; TI's
		// compiler keeps a loop's branches from being taken after one was not.
		if (st->nbr && b->target) {
			RZ_LOG_DEBUG("c6x: a branch to a computed target drops the branches in flight\n");
		} else if (st->nbr) {
			RZ_LOG_DEBUG("c6x: a branch to the loop at 0x%" PFMT64x " after it exited drops the branches in flight\n", b->target_const);
		}
		if (!b->target) {
			c6x_end_note(win, b->target_const);
		}
		return leave;
	}
	C6xWinState *fork = RZ_NEW(C6xWinState);
	if (!fork) {
		rz_il_op_effect_free(leave);
		return NULL;
	}
	*fork = *st;
	fork->pc = b->target_const;
	fork->cycle = at;
	fork->epi = NULL;
	fork->idle = 0;
	c6x_settle(fork, b, true);
	// two branches taking effect in one cycle are undefined, so those landing
	// with this one are not taken
	size_t keep = 0;
	for (size_t i = 0; i < fork->nbr; i++) {
		if (fork->br[i].issued + C6X_BRANCH_CYCLES > at) {
			fork->br[keep++] = fork->br[i];
		} else {
			c6x_flight_names_free(fork, &fork->br[i]);
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
	// the same arrival with no later branch taken
	C6xWinState *quiet = RZ_NEW(C6xWinState);
	if (!quiet) {
		rz_il_op_pure_free(later);
		rz_il_op_effect_free(leave);
		free(fork);
		return NULL;
	}
	*quiet = *fork;
	quiet->nbr = 0;
	for (size_t i = 0; i < fork->nbr; i++) {
		c6x_note_counted_out(quiet, &fork->br[i]);
		c6x_plog_tell(quiet, &fork->br[i], false);
		c6x_flight_names_free(quiet, &fork->br[i]);
	}
	RzILOpEffect *follow = NULL;
	bool ok = true;
	bool followed = false;
	if (fork->nbr) {
		follow = c6x_win_follow(win, fork, NULL);
		ok = follow;
	}
	bool hazard = ok && !surely && c6x_hazard_ahead(win, quiet);
	ut64 known = 0;
	bool carry = ok && !surely && !hazard && !win->plain && c6x_known_ahead(win, quiet, &known) && !c6x_ends_well(win, quiet->pc, known);
	if (hazard || carry) {
		// What is in flight lands in the code at the target, or what the path
		// knows decides a branch there that the ops from there do not lift
		// without.
		C6xWinMark mark;
		c6x_win_mark(win, &mark);
		if (carry) {
			quiet->carried = true;
			quiet->told = false;
			win->carries = true;
		}
		RzILOpEffect *on = c6x_win_follow(win, quiet, b);
		if (on) {
			rz_il_op_effect_free(leave);
			leave = on;
			followed = true;
		} else if (hazard) {
			c6x_refuse(win, "the code at 0x%" PFMT64x " is not followed for the results in flight to land", b->target_const);
			ok = false;
		} else {
			c6x_win_rewind(win, &mark);
		}
	}
	free(quiet);
	free(fork);
	if (!ok) {
		rz_il_op_pure_free(later);
		rz_il_op_effect_free(follow);
		rz_il_op_effect_free(leave);
		return NULL;
	}
	if (!follow) {
		rz_il_op_pure_free(later);
		if (!followed) {
			c6x_end_note(win, b->target_const);
		}
		return leave;
	}
	if (surely) {
		rz_il_op_effect_free(leave);
		return follow;
	}
	if (!followed) {
		c6x_end_note(win, b->target_const);
	}
	return BRANCH(later, follow, leave);
}

// The cycle of a period at whose start a SPLOOPW samples its condition for the
// stage boundary \p lag periods later: three cycles before that boundary
// (SPRUFE8B 7.10.2).
static void c6x_loop_sample_at(const C6xLoop *lp, RZ_OUT ut8 *lag, RZ_OUT ut8 *offset) {
	*lag = (lp->ii + 3) / lp->ii - 1;
	*offset = *lag * lp->ii + lp->ii - 4;
}

// When slot \p ls issues in period \p k, or in the period held in
// C6X_LOOP_PERIOD with \p dyn: a stage of an iteration that has started and
// not ended, the first iteration's alone for a masked slot, and not beside a
// masked slot on its unit. NULL when it always does, and *never set when it
// does not at all.
static RzILOpPure *c6x_loop_guard(const C6xLoop *lp, const C6xLoopSlot *ls, bool dyn, ut32 k, bool *never) {
	*never = false;
	bool w = lp->kind == C6X_INS_SPLOOPW;
	RzILOpPure *g = NULL;
	if (dyn) {
		if (ls->masked) {
			g = EQ(VARL(C6X_LOOP_PERIOD), U32(ls->stage));
		} else if (w) {
			g = ls->stage ? ULE(U32(ls->stage), VARL(C6X_LOOP_PERIOD)) : NULL;
		} else {
			// iterations count up from 0, so one that has not started wraps
			g = ULT(SUB(VARL(C6X_LOOP_PERIOD), U32(ls->stage)), VARL(C6X_LOOP_ITERS));
		}
	} else if (ls->masked ? k != ls->stage : k < ls->stage) {
		*never = true;
		return NULL;
	} else if (!ls->masked && !w) {
		g = ULT(U32(k - ls->stage), VARL(C6X_LOOP_ITERS));
	}
	for (size_t i = 0; !ls->masked && ls->unit != UT8_MAX && i < lp->nmask; i++) {
		const C6xLoopMask *m = &lp->mask[i];
		if (m->offset != ls->offset || m->stage == ls->stage || !((m->units >> ls->unit) & 1)) {
			continue;
		}
		if (!dyn) {
			if (k == m->stage) {
				rz_il_op_pure_free(g);
				*never = true;
				return NULL;
			}
			continue;
		}
		RzILOpPure *free_unit = INV(EQ(VARL(C6X_LOOP_PERIOD), U32(m->stage)));
		g = g ? AND(g, free_unit) : free_unit;
	}
	if (w && !dyn) {
		// a period lifted on its own may follow the boundary the loop ended on
		g = g ? AND(VARL(C6X_LOOP_RUNS), g) : VARL(C6X_LOOP_RUNS);
	}
	return g;
}

// Issue cycle \p r of a period of loop \p lp: period \p k, or the one held in
// C6X_LOOP_PERIOD with \p dyn.
static bool c6x_loop_cycle(C6xWin *win, C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps, const C6xLoop *lp, ut8 r, bool dyn, ut32 k) {
	if (!win->loop_budget || !win->work) {
		c6x_refuse(win, "lifting a SPLOOP issues more cycles than one lift may");
		return false;
	}
	win->loop_budget--;
	win->work--;
	c6x_land_before(st, st->cycle, steps);
	if (lp->kind == C6X_INS_SPLOOPW) {
		ut8 lag, at;
		c6x_loop_sample_at(lp, &lag, &at);
		if (r == at) {
			RzILOpPure *v = VARG(c6x_pred_reg_name(lp->creg));
			rz_pvector_push(steps, SETL(c6x_sample_names[0], lp->z ? IS_ZERO(v) : NON_ZERO(v)));
		}
	}
	C6xIssue *is = RZ_NEWS0(C6xIssue, C6X_CYCLE_SLOTS);
	if (!is) {
		return false;
	}
	size_t n = 0;
	bool ok = true;
	for (int stores = 0; stores < 2 && ok; stores++) {
		for (size_t i = 0; i < lp->nslot && ok; i++) {
			const C6xLoopSlot *ls = &lp->slot[i];
			if (ls->offset != r || c6x_writes_memory(&ls->insn) != stores) {
				continue;
			}
			bool never;
			RzILOpPure *g = c6x_loop_guard(lp, ls, dyn, k, &never);
			if (never) {
				continue;
			}
			ok = c6x_cycle_add(win, is, &n, &ls->insn, ls->addr, NULL, g);
		}
	}
	ok = ok && c6x_issue_cycle(win, st, steps, is, n, 0, st->cycle + 1, true);
	if (!ok) {
		c6x_issues_fini(is, n);
	}
	free(is);
	st->cycle++;
	return ok;
}

// The stage boundary ending period \p k, or the one in C6X_LOOP_PERIOD with
// \p dyn: a SPLOOPW stops on it when its condition failed three cycles before.
static void c6x_loop_boundary(const C6xLoop *lp, RzPVector /*<RzILOpEffect *>*/ *steps, bool dyn, ut32 k) {
	if (lp->kind != C6X_INS_SPLOOPW) {
		return;
	}
	ut8 lag, at;
	c6x_loop_sample_at(lp, &lag, &at);
	const char *sample = c6x_sample_names[lag];
	// the boundaries of the first three cycles are not tested
	if (dyn) {
		RzILOpPure *runs = lag ? OR(ULT(VARL(C6X_LOOP_PERIOD), U32(lag)), VARL(sample)) : VARL(sample);
		rz_pvector_push(steps, SETL(C6X_LOOP_RUNS, runs));
	} else if (k >= lag) {
		rz_pvector_push(steps, SETL(C6X_LOOP_RUNS, AND(VARL(C6X_LOOP_RUNS), VARL(sample))));
	}
	for (ut8 j = lag; j > 0; j--) {
		rz_pvector_push(steps, SETL(c6x_sample_names[j], VARL(c6x_sample_names[j - 1])));
	}
}

// Read the body of the SPLOOP \p lp from \p pc on, up to the execute packet of
// its SPKERNEL. False for what is not lifted: a reload, a branch in the body,
// a body too large for the loop buffer, or an instruction without IL.
static bool c6x_loop_decode(C6xWin *win, C6xLoop *lp, ut64 pc) {
	ut32 o = 0;
	for (size_t p = 0; p < C6X_LOOP_DYNLEN; p++) {
		C6xInsn slots[C6X_FP_SLOTS];
		C6xPacketRef pkt;
		size_t n = win->packet(win->user, pc, slots, &pkt);
		if (!n || pkt.addr != pc) {
			return false;
		}
		ut8 units = 0;
		bool kernel = false;
		for (size_t i = 0; i < n; i++) {
			switch (slots[i].id) {
			case C6X_INS_SPMASK:
				units |= slots[i].ops[0].v.units;
				break;
			case C6X_INS_SPKERNEL:
				kernel = true;
				lp->delay = c6x_spkernel_delay(&slots[i], lp->ii);
				break;
			case C6X_INS_SPKERNELR:
			case C6X_INS_SPMASKR:
			case C6X_INS_SPLOOP:
			case C6X_INS_SPLOOPD:
			case C6X_INS_SPLOOPW:
				c6x_refuse(win, "a SPLOOP that reloads or nests at 0x%" PFMT64x " is not lifted", pkt.slots[i].addr);
				return false;
			default:
				break;
			}
		}
		if (units) {
			lp->mask[lp->nmask++] = (C6xLoopMask){ o / lp->ii, o % lp->ii, units };
		}
		for (size_t i = 0; i < n; i++) {
			const C6xInsn *insn = &slots[i];
			if (insn->id == C6X_INS_NOP || insn->id == C6X_INS_SPMASK || insn->id == C6X_INS_SPKERNEL) {
				continue;
			}
			RzILOpEffect *eff = c6x_lift(insn, pkt.slots[i].addr);
			bool ok = eff && !c6x_effect_jumps(eff) && lp->nslot < C6X_LOOP_SLOTS;
			rz_il_op_effect_free(eff);
			if (!ok) {
				c6x_refuse(win, "%s at 0x%" PFMT64x " in a SPLOOP body is not lifted", rz_str_get_null(c6x_ins_name(insn->id)), pkt.slots[i].addr);
				return false;
			}
			C6xLoopSlot *ls = &lp->slot[lp->nslot++];
			ls->insn = *insn;
			ls->addr = pkt.slots[i].addr;
			ls->stage = o / lp->ii;
			ls->offset = o % lp->ii;
			ls->unit = c6x_unit_bit(insn);
			ls->masked = ls->unit != UT8_MAX && ((units >> ls->unit) & 1);
		}
		o += c6x_packet_cycles(slots, 0, n);
		if (o > C6X_LOOP_DYNLEN) {
			return false;
		}
		if (kernel) {
			lp->dynlen = o;
			lp->stages = (o + lp->ii - 1) / lp->ii;
			lp->post = pkt.next;
			// SPRUFE8B 7.7.3.3: the assembler rejects shorter bodies
			return o >= lp->ii + (lp->kind != C6X_INS_SPLOOPW);
		}
		pc = pkt.next;
	}
	return false;
}

// The results the periods of \p lp leave in flight across a stage boundary,
// into \p out: a slot at offset r whose result lands d cycles after it issues
// leaves it in flight over (r + d) / ii boundaries, due ii cycles sooner after
// each.
static bool c6x_loop_carried(const C6xLoop *lp, C6xLanding *out, size_t *n) {
	*n = 0;
	for (size_t i = 0; i < lp->nslot; i++) {
		const C6xLoopSlot *ls = &lp->slot[i];
		C6xIssue tmp = { 0 };
		tmp.insn = &ls->insn;
		RzILOpEffect *body = c6x_lift(&ls->insn, ls->addr);
		bool ok = c6x_collect_writes(body, false, &tmp);
		rz_il_op_effect_free(body);
		if (!ok) {
			return false;
		}
		for (size_t k = 0; k < tmp.nw; k++) {
			ut32 d = ls->offset + tmp.w[k].delay;
			for (ut32 a = 1; a <= d / lp->ii; a++) {
				ut32 due = d - a * lp->ii;
				for (size_t j = 0; j < *n; j++) {
					if (out[j].due == due && RZ_STR_EQ(out[j].reg, tmp.w[k].reg)) {
						RZ_LOG_DEBUG("c6x: two results of a SPLOOP land in %s at once\n", tmp.w[k].reg);
						return false;
					}
				}
				if (*n >= C6X_WIN_LANDINGS) {
					return false;
				}
				out[(*n)++] = (C6xLanding){ tmp.w[k].reg, NULL, NULL, due };
			}
		}
	}
	return true;
}

// The carried result \p canon holds what lands in \p reg in cycle \p due, or NULL.
static C6xLanding *c6x_carried_find(C6xLanding *canon, size_t n, const char *reg, ut32 due) {
	for (size_t i = 0; i < n; i++) {
		if (canon[i].due == due && RZ_STR_EQ(canon[i].reg, reg)) {
			return &canon[i];
		}
	}
	return NULL;
}

static int c6x_landing_cmp_due(const void *a, const void *b) {
	const C6xLanding *const *x = a;
	const C6xLanding *const *y = b;
	return (int)(x[0]->due > y[0]->due) - (int)(x[0]->due < y[0]->due);
}

// Move what \p st has in flight into the carried results \p canon, each due
// \p shift cycles sooner than what it moves in, and keep those in flight
// instead; a carried result nothing moves into is cleared.
static bool c6x_loop_carry(C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps, C6xLanding *canon, size_t ncanon, ut32 shift) {
	bool hit[C6X_WIN_LANDINGS] = { 0 };
	const C6xLanding *pair[C6X_WIN_LANDINGS][2];
	size_t npair = 0;
	for (size_t i = 0; i < st->nland; i++) {
		const C6xLanding *l = &st->land[i];
		C6xLanding *c = l->due >= shift ? c6x_carried_find(canon, ncanon, l->reg, l->due - shift) : NULL;
		if (!c || hit[c - canon]) {
			RZ_LOG_DEBUG("c6x: a result in flight to %s is not carried through the loop\n", l->reg);
			return false;
		}
		hit[c - canon] = true;
		pair[npair][0] = c;
		pair[npair][1] = l;
		npair++;
	}
	// a carried result moving up a period is read before the one behind it takes its place
	qsort(pair, npair, sizeof(pair[0]), c6x_landing_cmp_due);
	for (size_t i = 0; i < npair; i++) {
		const C6xLanding *c = pair[i][0], *l = pair[i][1];
		if (c->val == l->val) {
			continue;
		}
		rz_pvector_push(steps, SETL(c->val, VARL(l->val)));
		rz_pvector_push(steps, SETL(c->flag, l->flag ? VARL(l->flag) : IL_TRUE));
	}
	for (size_t i = 0; i < ncanon; i++) {
		if (!hit[i]) {
			rz_pvector_push(steps, SETL(canon[i].flag, IL_FALSE));
		}
	}
	return true;
}

// Run loop \p lp from its first cycle, st->cycle, then what follows it: its
// periods, those whose guards depend on the period alone as the body of a
// repeat. The iterations of a SPLOOP are the ILC it found, of a SPLOOPD the
// ILC its packet leaves plus those it runs regardless (SPRUFE8B Table 7-4); a
// SPLOOPW runs until its condition fails, and its epilog is skipped.
static RzILOpEffect *c6x_loop_run(C6xWin *win, C6xWinState *st, const C6xLoop *lp, bool main_path) {
	RzPVector steps;
	rz_pvector_init(&steps, NULL);
	RzILOpEffect *tail = NULL;
	ut8 ii = lp->ii;
	ut32 stages = lp->stages;
	bool w = lp->kind == C6X_INS_SPLOOPW;
	if (lp->kind == C6X_INS_SPLOOPD) {
		rz_pvector_push(&steps, SETL(C6X_LOOP_ITERS, ADD(VARG("ilc"), U32(1 + 3 / ii))));
	}
	// The code after the loop issues once the epilog has run for the SPKERNEL
	// delay, or once it has drained when that is sooner, or when the loop
	// exits before its kernel; then the buffer has only run whole stages.
	ut32 delay = RZ_MIN(lp->delay, (ut32)lp->dynlen - ii);
	ut32 skip = delay / ii, fetch = delay % ii;
	if (!w) {
		RzILOpPure *early = ITE(IS_ZERO(VARL(C6X_LOOP_ITERS)), U32(stages), ADD(VARL(C6X_LOOP_ITERS), U32(stages - 1)));
		rz_pvector_push(&steps, SETL(C6X_LOOP_END, ITE(ULT(VARL(C6X_LOOP_ITERS), U32(stages)), early, ADD(VARL(C6X_LOOP_ITERS), U32(skip)))));
	} else {
		rz_pvector_push(&steps, SETL(C6X_LOOP_RUNS, IL_TRUE));
		for (size_t j = 0; j < RZ_ARRAY_SIZE(c6x_sample_names); j++) {
			rz_pvector_push(&steps, SETL(c6x_sample_names[j], IL_TRUE));
		}
	}
	// the loop's own cycles count from its first period
	ut32 base = st->cycle;
	ut32 last = 0;
	for (size_t i = 0; i < st->nland; i++) {
		st->land[i].due -= base;
		last = RZ_MAX(last, st->land[i].due + 1);
	}
	st->cycle = 0;
	memset(st->pred_written, 0, sizeof(st->pred_written));
	memset(st->ctr_written, 0, sizeof(st->ctr_written));
	c6x_plog_reset(st);
	// the periods results from before the loop land in are lifted on their own
	ut32 peel = (last + ii - 1) / ii;
	if (!w && peel > stages) {
		c6x_refuse(win, "a result lands too late in the SPLOOP before 0x%" PFMT64x "", lp->post);
		goto fail;
	}
	for (ut32 k = 0; k < peel; k++) {
		for (ut8 r = 0; r < ii; r++) {
			if (!c6x_loop_cycle(win, st, &steps, lp, r, false, k)) {
				goto fail;
			}
		}
		c6x_loop_boundary(lp, &steps, false, k);
	}
	c6x_land_before(st, st->cycle, &steps);
	for (size_t i = 0; i < st->nland; i++) {
		st->land[i].due -= st->cycle;
	}
	st->cycle = 0;
	// what one period leaves in flight for the next one is carried in locals
	// the repetitions share
	C6xLanding canon[C6X_WIN_LANDINGS];
	size_t ncanon;
	if (!c6x_loop_carried(lp, canon, &ncanon)) {
		goto fail;
	}
	for (size_t i = 0; i < ncanon; i++) {
		canon[i].val = c6x_val_take(st, C6X_NAME_PINNED);
		canon[i].flag = c6x_flag_take(st, C6X_NAME_PINNED);
		if (!canon[i].val || !canon[i].flag) {
			c6x_refuse(win, "too many results in flight in the SPLOOP before 0x%" PFMT64x "", lp->post);
			goto fail;
		}
		rz_pvector_push(&steps, SETL(canon[i].val, U32(0)));
	}
	if (!c6x_loop_carry(st, &steps, canon, ncanon, 0)) {
		goto fail;
	}
	for (size_t i = 0; i < st->nland; i++) {
		c6x_landing_names(st, &st->land[i], C6X_NAME_FREE);
	}
	memcpy(st->land, canon, ncanon * sizeof(C6xLanding));
	st->nland = ncanon;
	rz_pvector_push(&steps, SETL(C6X_LOOP_PERIOD, U32(peel)));
	// the repeated period
	C6xWinState *bs = RZ_NEW(C6xWinState);
	if (!bs) {
		goto fail;
	}
	*bs = *st;
	RzPVector body;
	rz_pvector_init(&body, NULL);
	bool ok = true;
	for (ut8 r = 0; r < ii && ok; r++) {
		ok = c6x_loop_cycle(win, bs, &body, lp, r, true, 0);
	}
	if (ok) {
		c6x_land_before(bs, ii, &body);
		c6x_loop_boundary(lp, &body, true, 0);
		ok = c6x_loop_carry(bs, &body, canon, ncanon, ii);
	}
	free(bs);
	if (!ok) {
		c6x_steps_free(&body);
		rz_pvector_fini(&body);
		goto fail;
	}
	rz_pvector_push(&body, SETL(C6X_LOOP_PERIOD, ADD(VARL(C6X_LOOP_PERIOD), U32(1))));
	RzILOpPure *again = w ? VARL(C6X_LOOP_RUNS) : ULT(VARL(C6X_LOOP_PERIOD), VARL(C6X_LOOP_END));
	rz_pvector_push(&steps, REPEAT(again, c6x_seal(&body, NULL)));
	rz_pvector_fini(&body);
	for (size_t i = 0; i < st->nland; i++) {
		c6x_landing_names(st, &st->land[i], C6X_NAME_USED);
	}
	// what the loop wrote is not known cycle by cycle
	for (size_t c = 0; c < RZ_ARRAY_SIZE(st->pred_written); c++) {
		st->pred_written[c] = 1;
	}
	for (size_t c = 0; c < RZ_ARRAY_SIZE(st->ctr_written); c++) {
		st->ctr_written[c] = 1;
	}
	c6x_plog_reset(st);
	st->pc = lp->post;
	if (w) {
		tail = c6x_win_run(win, st, main_path, false);
		if (!tail) {
			goto fail;
		}
	} else {
		// ILC counts down to zero; after an early exit the code after the
		// loop issues with the buffer drained, otherwise the epilog drains
		// beside it
		rz_pvector_push(&steps, SETG("ilc", U32(0)));
		C6xWinState *es = RZ_NEW(C6xWinState);
		if (!es) {
			goto fail;
		}
		*es = *st;
		RzILOpEffect *exit_early = c6x_win_run(win, es, false, false);
		free(es);
		if (!exit_early) {
			goto fail;
		}
		if (skip + 1 < stages) {
			st->epi = lp;
			st->epi_first = (ut8)skip;
			st->epi_base = 0;
			st->epi_end = lp->dynlen - (skip + 1) * ii;
			st->idle = fetch;
		}
		RzILOpEffect *drain = c6x_win_run(win, st, main_path, false);
		if (!drain) {
			rz_il_op_effect_free(exit_early);
			goto fail;
		}
		tail = BRANCH(ULT(VARL(C6X_LOOP_ITERS), U32(stages)), exit_early, drain);
	}
	RzILOpEffect *eff = c6x_seal(&steps, tail);
	rz_pvector_fini(&steps);
	return eff;
fail:
	c6x_steps_free(&steps);
	rz_pvector_fini(&steps);
	return NULL;
}

// Whether control, just taken to st->pc, enters a loop pipelined around its
// branch, into \p lp. With branches to there still in flight, they take effect
// a whole number of iterations apart, an iteration being the packets from
// st->pc issued in the cycles until the first of them does, and those packets
// hold one branch, back to st->pc, taking effect at the start of an iteration
// too. With none, the branch \p own that brought control here is the loop's
// one: the packets from st->pc issue it again, and an iteration ends as it
// takes effect. A branch issued after it on the opposite of its predicate
// leaves the loop as it exits: TI's compiler puts the return of a function
// that ends in a loop there.
static bool c6x_bloop_find(C6xWin *win, const C6xWinState *st, RZ_NULLABLE const C6xFlight *own, C6xBLoop *lp) {
	memset(lp, 0, sizeof(*lp));
	lp->start = st->pc;
	lp->len = UT32_MAX;
	for (size_t i = 0; i < st->nbr; i++) {
		const C6xFlight *o = &st->br[i];
		if (o->target || o->target_const != st->pc || o->loop) {
			return false;
		}
		lp->len = RZ_MIN(lp->len, o->issued + C6X_BRANCH_CYCLES - st->cycle);
	}
	if (!st->nbr && !own) {
		return false;
	}
	ut32 lands = 0;
	for (size_t i = 0; i < st->nbr; i++) {
		// two branches taking effect in one cycle are undefined
		ut32 d = st->br[i].issued + C6X_BRANCH_CYCLES - st->cycle;
		if (d % lp->len || (lands >> d) & 1) {
			return false;
		}
		lands |= 1u << d;
	}
	ut64 pc = st->pc;
	ut32 cycles = 0;
	ut32 branch_at = UT32_MAX;
	ut8 creg = 0; // the predicate its branch is taken on alone
	bool z = false;
	while (cycles < lp->len) {
		C6xInsn slots[C6X_FP_SLOTS];
		C6xPacketRef pkt;
		size_t n = win->packet(win->user, pc, slots, &pkt);
		if (!n || pkt.addr != pc || (pkt.n == 1 && pkt.slots[0].header) || lp->n >= C6X_BLOOP_PACKETS) {
			return false;
		}
		for (size_t i = 0; i < n; i++) {
			if (c6x_is_sploop(&slots[i])) {
				return false;
			}
			RzILOpEffect *eff = c6x_slot_body(&slots[i], pkt.slots[i].addr, &pkt);
			if (!eff) {
				return false;
			}
			bool ok = true;
			if (c6x_effect_jumps(eff)) {
				C6xIssue tmp = { 0 };
				tmp.taken = c6x_taken_names[0];
				tmp.target = c6x_target_names[0];
				eff = c6x_capture_jump(eff, false, &tmp, &ok);
				bool plain = slots[i].id == C6X_INS_B || slots[i].id == C6X_INS_BNOP;
				bool back = tmp.target_is_const && tmp.target_const == lp->start;
				if (ok && branch_at != UT32_MAX && !back) {
					ok = plain && tmp.jump_cond && creg && slots[i].creg == creg && slots[i].z != z;
					lp->outs++;
				} else {
					ok = ok && back && branch_at == UT32_MAX && (st->nbr || pkt.slots[i].addr == own->addr);
					branch_at = cycles;
					creg = plain && tmp.jump_cond ? slots[i].creg : 0;
					z = slots[i].z;
					if (ok && !st->nbr) {
						lp->len = cycles + C6X_BRANCH_CYCLES;
					}
				}
			}
			rz_il_op_effect_free(eff);
			if (!ok) {
				return false;
			}
		}
		lp->pc[lp->n] = pc;
		lp->at[lp->n++] = cycles;
		cycles += c6x_packet_cycles(slots, 0, n);
		pc = pkt.next;
	}
	lp->end = pc;
	if (cycles != lp->len || branch_at == UT32_MAX || (branch_at + C6X_BRANCH_CYCLES) % lp->len) {
		return false;
	}
	lp->lag = (branch_at + C6X_BRANCH_CYCLES) / lp->len;
	// a branch out takes effect after the loop only when its own ends the iteration
	return !lp->outs || lp->lag == 1;
}

static bool c6x_bloop_add(C6xLanding *out, size_t *n, const char *reg, ut32 due) {
	if (c6x_carried_find(out, *n, reg, due)) {
		return true;
	}
	if (*n >= C6X_WIN_LANDINGS) {
		RZ_LOG_DEBUG("c6x: too many results in flight in a loop\n");
		return false;
	}
	out[(*n)++] = (C6xLanding){ reg, NULL, NULL, due };
	return true;
}

// The results in flight across an iteration boundary of loop \p lp, into
// \p out: those the kernel leaves in flight, and those in flight in \p st as
// the loop starts, each due an iteration sooner after every boundary.
static bool c6x_bloop_carried(C6xWin *win, const C6xBLoop *lp, const C6xWinState *st, C6xLanding *out, size_t *n) {
	*n = 0;
	for (size_t p = 0; p < lp->n; p++) {
		C6xInsn slots[C6X_FP_SLOTS];
		C6xPacketRef pkt;
		size_t ns = win->packet(win->user, lp->pc[p], slots, &pkt);
		for (size_t i = 0; i < ns; i++) {
			C6xIssue tmp = { 0 };
			tmp.insn = &slots[i];
			RzILOpEffect *body = c6x_slot_body(&slots[i], pkt.slots[i].addr, &pkt);
			bool ok = c6x_collect_writes(body, false, &tmp);
			rz_il_op_effect_free(body);
			if (!ok) {
				return false;
			}
			for (size_t k = 0; k < tmp.nw; k++) {
				ut32 d = lp->at[p] + tmp.w[k].delay;
				for (ut32 a = 1; a <= d / lp->len; a++) {
					if (!c6x_bloop_add(out, n, tmp.w[k].reg, d - a * lp->len)) {
						return false;
					}
				}
			}
		}
	}
	for (size_t i = 0; i < st->nland; i++) {
		const C6xLanding *l = &st->land[i];
		for (ut32 a = 0; a <= l->due / lp->len; a++) {
			if (!c6x_bloop_add(out, n, l->reg, l->due - a * lp->len)) {
				return false;
			}
		}
	}
	return true;
}

// Whether the kernel of loop \p lp keeps a zero in the predicate register
// \p creg: it only clears the register, or writes it when it is not zero.
static bool c6x_bloop_keeps_zero(C6xWin *win, const C6xBLoop *lp, ut8 creg) {
	const char *reg = c6x_pred_reg_name(creg);
	for (size_t p = 0; p < lp->n; p++) {
		C6xInsn slots[C6X_FP_SLOTS];
		C6xPacketRef pkt;
		size_t ns = win->packet(win->user, lp->pc[p], slots, &pkt);
		for (size_t i = 0; i < ns; i++) {
			const C6xInsn *insn = &slots[i];
			C6xIssue tmp = { 0 };
			tmp.insn = insn;
			RzILOpEffect *body = c6x_slot_body(insn, pkt.slots[i].addr, &pkt);
			bool ok = c6x_collect_writes(body, false, &tmp);
			rz_il_op_effect_free(body);
			if (!ok) {
				return false;
			}
			bool clears = insn->id == C6X_INS_ZERO ||
				(insn->id == C6X_INS_MVK && insn->nops == 2 && insn->ops[0].kind == C6X_OP_IMM && !insn->ops[0].v.imm.value);
			bool guarded = insn->creg == creg && !insn->z;
			for (size_t k = 0; k < tmp.nw; k++) {
				if (RZ_STR_EQ(tmp.w[k].reg, reg) && (tmp.w[k].delay || !(clears || guarded))) {
					return false;
				}
			}
		}
	}
	return true;
}

// Whether a branch in flight to a loop as it starts in \p st not being taken
// leaves the later ones not taken, and their predicate register zero as the
// loop starts: they are taken on that one register not being zero, into
// \p creg, and nothing writes it otherwise in between. Branches always taken
// may come before them; \p creg is 0 with no other.
static bool c6x_bloop_entry_latched(const C6xWinState *st, RZ_OUT ut8 *creg) {
	*creg = 0;
	C6xWinState *tmp = RZ_NEW(C6xWinState);
	if (!tmp) {
		return false;
	}
	bool ok = true;
	const C6xFlight *prev = NULL;
	ut32 after = 0;
	for (size_t done = 0; ok && done < st->nbr; done++) {
		// in the order they issued
		const C6xFlight *o = NULL;
		for (size_t i = 0; i < st->nbr; i++) {
			const C6xFlight *x = &st->br[i];
			if ((!done || x->issued > after) && (!o || x->issued < o->issued)) {
				o = x;
			}
		}
		if (!o) {
			ok = false;
			break;
		}
		after = o->issued;
		if (!o->taken) {
			ok = !prev;
			continue;
		}
		ok = o->creg && !o->z && (!prev || prev->creg == o->creg);
		if (ok && prev) {
			*tmp = *st;
			c6x_plog_tell(tmp, prev, false);
			ok = c6x_pred_known(tmp, o->creg, o->issued) == C6X_PRED_ZERO;
		}
		prev = o;
	}
	if (ok && prev) {
		*tmp = *st;
		c6x_plog_tell(tmp, prev, false);
		ok = c6x_pred_known(tmp, prev->creg, st->cycle) == C6X_PRED_ZERO;
		*creg = prev->creg;
	}
	free(tmp);
	return ok;
}

// Issue the kernel packet at \p pc of loop \p lp in cycle \p at of an iteration.
static bool c6x_bloop_cycle(C6xWin *win, C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps, ut64 pc, ut32 at) {
	if (!win->loop_budget || !win->work) {
		c6x_refuse(win, "lifting a loop issues more cycles than one lift may");
		return false;
	}
	win->loop_budget--;
	win->work--;
	c6x_land_before(st, at, steps);
	st->cycle = at;
	C6xInsn slots[C6X_FP_SLOTS];
	C6xPacketRef pkt;
	size_t n = win->packet(win->user, pc, slots, &pkt);
	C6xIssue *is = RZ_NEWS0(C6xIssue, C6X_CYCLE_SLOTS);
	if (!n || !is) {
		free(is);
		return false;
	}
	size_t nis = 0;
	bool ok = true;
	for (int stores = 0; stores < 2 && ok; stores++) {
		for (size_t i = 0; i < n && ok; i++) {
			if (c6x_writes_memory(&slots[i]) == stores) {
				ok = c6x_cycle_add(win, is, &nis, &slots[i], pkt.slots[i].addr, &pkt, NULL);
			}
		}
	}
	// the iteration repeats, so what lands later is kept in flight
	ok = ok && c6x_issue_cycle(win, st, steps, is, nis, 0, at + 1, true);
	if (!ok) {
		c6x_issues_fini(is, nis);
	}
	free(is);
	st->cycle = at + 1;
	return ok;
}

// Run loop \p lp, pipelined around its branch, from st->pc, where a branch has
// just taken control, then what follows it. Its iterations are the body of a
// repeat: one runs when the branch taking effect at its start is taken, as the
// iteration lag before it decided when its branch issued. The taken flags of
// the branches in flight move up an iteration on every repetition, and so do
// the results in flight across a boundary, those from before the loop among
// them. When a branch is not taken, the code after the kernel issues with the
// results still in flight, and with the later branches unless that leaves none
// of them taken: BDECs counting one register down, or branches on a predicate
// register that stays zero.
static RzILOpEffect *c6x_win_bloop(C6xWin *win, C6xWinState *st, const C6xBLoop *lp) {
	RzPVector steps;
	rz_pvector_init(&steps, NULL);
	ut32 len = lp->len, lag = lp->lag;
	// Whether the branches in flight are BDECs counting one register down that
	// nothing else has written since the first of them issued: \c ctr is one
	// more than that register then, or 0 with none in flight.
	bool counted = true;
	ut8 ctr = 0;
	bool ctr_pred = false;
	ut32 first = UT32_MAX;
	for (size_t i = 0; i < st->nbr; i++) {
		const C6xFlight *o = &st->br[i];
		counted = counted && o->ctr && (!ctr || (o->ctr == ctr && o->ctr_pred == ctr_pred));
		ctr = o->ctr;
		ctr_pred = o->ctr_pred;
		first = RZ_MIN(first, o->issued);
	}
	for (size_t i = 0; counted && i < st->nbr; i++) {
		counted = st->br[i].ctr_written <= first && st->ctr_written[ctr - 1] <= first;
	}
	// Or branches on a predicate register that stays zero once it is: TI's
	// compiler clears it for the loop to end, so that a branch not taken leaves
	// none of the later ones taken either.
	ut8 latch = 0;
	bool latched = c6x_bloop_entry_latched(st, &latch);
	ut8 landing = 0; // the predicate registers a result is in flight to, by creg
	for (size_t i = 0; i < st->nland; i++) {
		landing |= 1u << c6x_creg_of(st->land[i].reg);
	}
	memset(st->ctr_out, 0, sizeof(st->ctr_out));
	c6x_plog_reset(st);
	// the loop's own cycles count from its first iteration
	ut32 base = st->cycle;
	for (size_t i = 0; i < st->nland; i++) {
		st->land[i].due -= base;
	}
	for (ut32 k = 1; k < lag; k++) {
		const C6xFlight *o = NULL;
		for (size_t i = 0; i < st->nbr && !o; i++) {
			if (st->br[i].issued + C6X_BRANCH_CYCLES - base == k * len) {
				o = &st->br[i];
			}
		}
		RzILOpPure *v;
		if (!o) {
			// without a branch taking effect at its start, control leaves the kernel
			v = IL_FALSE;
		} else {
			v = o->taken ? VARL(o->taken) : IL_TRUE;
		}
		rz_pvector_push(&steps, SETL(c6x_bq_names[k - 1], v));
	}
	for (size_t i = 0; i < st->nbr; i++) {
		c6x_flight_names_free(st, &st->br[i]);
	}
	st->nbr = 0;
	st->cycle = 0;
	C6xLanding canon[C6X_WIN_LANDINGS];
	size_t ncanon;
	if (!c6x_bloop_carried(win, lp, st, canon, &ncanon)) {
		goto fail;
	}
	for (size_t i = 0; i < ncanon; i++) {
		canon[i].val = c6x_val_take(st, C6X_NAME_PINNED);
		canon[i].flag = c6x_flag_take(st, C6X_NAME_PINNED);
		if (!canon[i].val || !canon[i].flag) {
			c6x_refuse(win, "too many results in flight in the loop at 0x%" PFMT64x "", lp->start);
			goto fail;
		}
		rz_pvector_push(&steps, SETL(canon[i].val, U32(0)));
	}
	if (!c6x_loop_carry(st, &steps, canon, ncanon, 0)) {
		goto fail;
	}
	for (size_t i = 0; i < st->nland; i++) {
		c6x_landing_names(st, &st->land[i], C6X_NAME_FREE);
	}
	memcpy(st->land, canon, ncanon * sizeof(C6xLanding));
	st->nland = ncanon;
	rz_pvector_push(&steps, SETL(C6X_BLOOP_RUNS, IL_TRUE));
	// the repeated iteration
	C6xWinState *bs = RZ_NEW(C6xWinState);
	if (!bs) {
		goto fail;
	}
	*bs = *st;
	memset(bs->ctr_written, 0, sizeof(bs->ctr_written));
	memset(bs->pred_written, 0, sizeof(bs->pred_written));
	RzPVector body;
	rz_pvector_init(&body, NULL);
	bool ok = true;
	for (size_t i = 0; i < lp->n && ok; i++) {
		ok = c6x_bloop_cycle(win, bs, &body, lp->pc[i], lp->at[i]);
	}
	if (ok) {
		c6x_land_before(bs, len, &body);
		ok = bs->nbr == 1 + lp->outs;
	}
	// the kernel's branch, the first to issue, and those out of the loop
	C6xFlight outs[C6X_WIN_BRANCHES];
	for (size_t i = 1; ok && i < bs->nbr; i++) {
		// taken when the kernel's is not, on the value that one tested
		outs[i - 1] = bs->br[i];
		ok = bs->br[i].z != bs->br[0].z && c6x_same_test(&bs->br[0], &bs->br[i]);
	}
	if (ok) {
		// the kernel's branch is one of them, and nothing else in it writes the counter
		const C6xFlight *o = &bs->br[0];
		counted = counted && o->ctr && (!ctr || (o->ctr == ctr && o->ctr_pred == ctr_pred)) && !bs->ctr_written[o->ctr - 1];
		ctr = o->ctr;
		ctr_pred = o->ctr_pred;
		latched = latched && o->creg && !o->z && (!latch || latch == o->creg) && !((landing >> o->creg) & 1) &&
			c6x_bloop_keeps_zero(win, lp, o->creg);
		latch = o->creg;
	}
	if (ok) {
		// the branch of this iteration takes effect at the start of the one lag on
		const char *taken = bs->br[0].taken;
		rz_pvector_push(&body, SETL(c6x_bq_names[lag - 1], taken ? VARL(taken) : IL_TRUE));
		bs->nbr = 0;
		rz_pvector_push(&body, SETL(C6X_BLOOP_RUNS, VARL(c6x_bq_names[0])));
		for (ut32 k = 0; k + 1 < lag; k++) {
			rz_pvector_push(&body, SETL(c6x_bq_names[k], VARL(c6x_bq_names[k + 1])));
		}
		ok = c6x_loop_carry(bs, &body, canon, ncanon, len);
	}
	free(bs);
	if (!ok) {
		c6x_steps_free(&body);
		rz_pvector_fini(&body);
		goto fail;
	}
	rz_pvector_push(&steps, REPEAT(VARL(C6X_BLOOP_RUNS), c6x_seal(&body, NULL)));
	rz_pvector_fini(&body);
	// cycles count on from where the loop exited, late enough for its last
	// branches to have issued in them
	st->cycle = C6X_BRANCH_CYCLES;
	for (size_t i = 0; i < st->nland; i++) {
		c6x_landing_names(st, &st->land[i], C6X_NAME_USED);
		st->land[i].due += st->cycle;
	}
	// what the loop wrote is not known cycle by cycle
	for (size_t c = 0; c < RZ_ARRAY_SIZE(st->pred_written); c++) {
		st->pred_written[c] = st->cycle;
	}
	for (size_t c = 0; c < RZ_ARRAY_SIZE(st->ctr_written); c++) {
		st->ctr_written[c] = st->cycle;
	}
	c6x_plog_reset(st);
	if (counted) {
		// the BDEC that was not taken leaves none of those after it taken
		C6xFlight out = { 0 };
		out.issued = st->cycle;
		out.ctr = ctr;
		out.ctr_pred = ctr_pred;
		c6x_note_counted_out(st, &out);
	}
	if (latched) {
		// the register is zero, as the branch that was not taken found it
		C6xPlogEntry e = { st->cycle, C6X_PLOG_IS, latch, C6X_PRED_ZERO, 0, false, st->cycle };
		c6x_plog_add(st, e);
	}
	for (ut32 k = 1; k < lag && !counted && !latched; k++) {
		C6xFlight *o = &st->br[st->nbr++];
		memset(o, 0, sizeof(*o));
		o->issued = st->cycle + k * len - C6X_BRANCH_CYCLES;
		o->taken = c6x_bq_names[k - 1];
		o->target_const = lp->start;
		o->loop = true;
	}
	for (size_t i = 0; i < lp->outs; i++) {
		// taken in the iteration the loop exited from, with the target it read then
		C6xFlight *o = &st->br[st->nbr++];
		memset(o, 0, sizeof(*o));
		o->issued = st->cycle + outs[i].issued - len;
		o->target = outs[i].target;
		o->target_const = outs[i].target_const;
		o->addr = outs[i].addr;
		c6x_name_set(c6x_target_names, st->target_state, RZ_ARRAY_SIZE(c6x_target_names), o->target, C6X_NAME_USED);
	}
	st->pc = lp->end;
	RzILOpEffect *tail = c6x_win_run(win, st, false, true);
	if (!tail) {
		goto fail;
	}
	RzILOpEffect *eff = c6x_seal(&steps, tail);
	rz_pvector_fini(&steps);
	return eff;
fail:
	c6x_steps_free(&steps);
	rz_pvector_fini(&steps);
	return NULL;
}

// Lift the SPLOOP whose execute packet is at st->pc and what follows it: the
// packet's other slots issue once, then the loop runs. A branch issued before
// may take effect as the loop would start, as when a function returns early
// in place of a loop it began in the delay slots: the loop buffer goes idle
// once a branch is taken, so the loop runs only when that one is not.
// Reloading loops are not lifted.
static RzILOpEffect *c6x_win_sploop(C6xWin *win, C6xWinState *st, RzPVector /*<RzILOpEffect *>*/ *steps, bool main_path) {
	if (st->epi || win->nloops >= C6X_WIN_LOOPS) {
		c6x_refuse(win, "a SPLOOP at 0x%" PFMT64x " beside another loop is not lifted", st->pc);
		return NULL;
	}
	C6xInsn slots[C6X_FP_SLOTS];
	C6xPacketRef pkt;
	size_t n = win->packet(win->user, st->pc, slots, &pkt);
	size_t first = 0;
	while (first < n && pkt.slots[first].addr != st->pc) {
		first++;
	}
	C6xLoop *lp = RZ_NEW0(C6xLoop);
	if (first == n || !lp) {
		free(lp);
		return NULL;
	}
	win->loops[win->nloops++] = lp;
	const C6xInsn *sp = &slots[first];
	lp->kind = sp->id;
	lp->ii = (ut8)sp->ops[0].v.imm.value;
	lp->creg = sp->creg;
	lp->z = sp->z;
	bool w = lp->kind == C6X_INS_SPLOOPW;
	if (!lp->ii || w != !!c6x_pred_reg_name(lp->creg)) {
		// a predicated SPLOOP(D) reloads, and a SPLOOPW is always predicated
		c6x_refuse(win, "a SPLOOP that reloads at 0x%" PFMT64x " is not lifted", st->pc);
		return NULL;
	}
	if (!c6x_loop_decode(win, lp, pkt.next)) {
		return NULL;
	}
	if (lp->kind == C6X_INS_SPLOOP) {
		rz_pvector_push(steps, SETL(C6X_LOOP_ITERS, VARG("ilc")));
	}
	// the slots beside the SPLOOP issue once
	C6xIssue *is = RZ_NEWS0(C6xIssue, C6X_CYCLE_SLOTS);
	if (!is) {
		return NULL;
	}
	size_t nis = 0;
	bool ok = true;
	size_t nbr = st->nbr;
	for (int stores = 0; stores < 2 && ok; stores++) {
		for (size_t i = first + 1; i < n && ok; i++) {
			if (c6x_writes_memory(&slots[i]) == stores) {
				ok = c6x_cycle_add(win, is, &nis, &slots[i], pkt.slots[i].addr, &pkt, NULL);
			}
		}
	}
	ok = ok && c6x_issue_cycle(win, st, steps, is, nis, 0, st->cycle + 1, true);
	if (!ok) {
		c6x_issues_fini(is, nis);
	}
	free(is);
	if (!ok) {
		return NULL;
	}
	st->pc = pkt.next;
	st->cycle++;
	c6x_land_before(st, st->cycle, steps);
	if (st->nbr != nbr || st->nbr > 1 || (st->nbr && st->br[0].issued + C6X_BRANCH_CYCLES != st->cycle)) {
		c6x_refuse(win, "a SPLOOP at 0x%" PFMT64x " running into a branch is not lifted", pkt.slots[first].addr);
		return NULL;
	}
	if (!st->nbr) {
		return c6x_loop_run(win, st, lp, main_path);
	}
	C6xFlight b = st->br[0];
	st->nbr = 0;
	c6x_flight_names_free(st, &b);
	RzILOpEffect *taken = c6x_win_taken(win, st, &b, st->cycle);
	if (!taken) {
		return NULL;
	}
	if (!b.taken) {
		if (main_path && !win->has_end) {
			win->end = st->pc;
			win->has_end = true;
		}
		return taken;
	}
	RzILOpEffect *run = c6x_loop_run(win, st, lp, main_path);
	if (!run) {
		rz_il_op_effect_free(taken);
		return NULL;
	}
	return BRANCH(VARL(b.taken), taken, run);
}

// Lift from \p st on: issue packets until no branch is in flight and nothing
// reads a result before it lands, then write what is in flight and leave. The
// lift goes on past a branch ahead that the path knows is not taken, when that
// takes no other branch into it.
static RzILOpEffect *c6x_win_run(C6xWin *win, C6xWinState *st, bool main_path, bool issue_first) {
	RzPVector steps;
	rz_pvector_init(&steps, NULL);
	RzILOpEffect *tail = NULL;
	for (bool check = !issue_first;; check = true) {
		if (!st->epi && st->idle) {
			st->cycle += st->idle;
			st->idle = 0;
		}
		if (check) {
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
				// its flag and target are read as it takes effect, before any reuse
				c6x_flight_names_free(st, &b);
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
			if (!st->nbr && !st->epi && !c6x_hazard_ahead(win, st)) {
				ut64 known = 0;
				if (!win->plain && c6x_known_ahead(win, st, &known) && !c6x_ends_well(win, st->pc, known)) {
					// Ending here would lose what decides a branch ahead, and the
					// ops from here do not lift without it.
					C6xWinMark mark;
					c6x_win_mark(win, &mark);
					C6xWinState *on = RZ_NEW(C6xWinState);
					if (on) {
						*on = *st;
						on->carried = true;
						on->told = false;
						win->carries = true;
						tail = c6x_win_run(win, on, main_path, true);
						free(on);
					}
					if (tail) {
						break;
					}
					c6x_win_rewind(win, &mark);
				}
				if (st->carried && !st->told) {
					// What it was lifted on for is gone before the branch: the op
					// ends where it would have, not some packets into that code.
					c6x_refuse(win, "a path lifted on for what it knows ends at 0x%" PFMT64x " with no branch decided", st->pc);
					goto fail;
				}
				c6x_end_note(win, st->pc);
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
		}
		if (st->idle) {
			if (!c6x_win_idle(win, st, &steps)) {
				goto fail;
			}
			continue;
		}
		C6xIssueResult r = c6x_win_issue(win, st, &steps);
		if (r == C6X_ISSUE_LOOP) {
			tail = c6x_win_sploop(win, st, &steps, main_path);
			if (!tail) {
				goto fail;
			}
			break;
		}
		if (r != C6X_ISSUE_OK) {
			goto fail;
		}
	}
	RzILOpEffect *eff = c6x_seal(&steps, tail);
	rz_pvector_fini(&steps);
	return eff;
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
 *         without IL, a packet that cannot be read, a branch to follow into a
 *         computed target, or a SPLOOP that reloads.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift_window(C6xPacketFn packet, void *user, ut64 addr, ut64 fall, RZ_OUT ut64 *end) {
	rz_return_val_if_fail(packet && end, NULL);
	C6xWin win;
	c6x_win_init(&win, packet, user, fall, false);
	RzILOpEffect *eff = c6x_window(&win, addr, end);
	if (!eff && win.carries) {
		// what its paths were lifted on with is not left for the others
		c6x_win_init(&win, packet, user, fall, true);
		eff = c6x_window(&win, addr, end);
	}
	if (!eff && *win.why) {
		RZ_LOG_VERBOSE("c6x: no IL at 0x%" PFMT64x ": %s\n", addr, win.why);
	}
	return eff;
}

// Set \p win up for a lift. With \p plain every path ends where it can.
static void c6x_win_init(C6xWin *win, C6xPacketFn packet, void *user, ut64 fall, bool plain) {
	memset(win, 0, sizeof(*win));
	win->packet = packet;
	win->user = user;
	win->fall = fall;
	win->plain = plain;
	win->budget = C6X_WIN_PACKETS;
	win->loop_budget = C6X_LOOP_CYCLES;
	win->work = C6X_WIN_WORK;
	win->probe = C6X_WIN_WORK;
}

// c6x_lift_window() for once, as \p win is set up. It tells whether a path
// was lifted on for what it knows and why there is no IL; when plain and asked
// to, where the paths leave to.
static RzILOpEffect *c6x_window(C6xWin *win, ut64 addr, RZ_OUT ut64 *end) {
	*end = 0;
	C6xInsn slots[C6X_FP_SLOTS];
	C6xPacketRef pkt;
	if (!win->packet(win->user, addr, slots, &pkt)) {
		return NULL;
	}
	if (pkt.n == 1 && pkt.slots[0].header) {
		// not an instruction: execution runs past it
		*end = pkt.next;
		return win->fall == C6X_FALL_TO_END || win->fall == pkt.next ? NOP() : JMP(U32((ut32)pkt.next));
	}
	C6xWinState *st = RZ_NEW0(C6xWinState);
	if (!st) {
		return NULL;
	}
	st->pc = addr;
	RzILOpEffect *eff = c6x_win_run(win, st, true, true);
	free(st);
	for (size_t i = 0; i < win->nloops; i++) {
		free(win->loops[i]);
	}
	win->nloops = 0;
	*end = win->has_end ? win->end : pkt.next;
	return eff;
}

#include <rz_il/rz_il_opbuilder_end.h>
